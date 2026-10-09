"""Transactional synthetic bank. No real settlement and no genuine identity verification."""

import asyncio
import hashlib
import json
from contextlib import asynccontextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from aegis.common.ids import new_id
from aegis.control import ledger
from aegis.control.bank_tables import BankAccount, BankCustomer, BankDocument, BankEntry, BankOperation, BankPayment
from aegis_demo.data import CUSTOMERS, DOCUMENTS, LANDLORD_IBAN

SEED_CUSTOMERS = deepcopy(CUSTOMERS)
SEED_DOCUMENTS = deepcopy(DOCUMENTS)


@dataclass(frozen=True)
class Execution:
    subject: str
    root_id: str
    mandate_id: str
    agent_id: str


def digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def receipt_hash(root_id: str, tool: str, arguments_hash: str) -> str:
    value = digest({"root": root_id, "tool": tool, "arguments_hash": arguments_hash})
    # Colon-separated bytes cannot accidentally match a phone/BSN/IBAN recognizer. No PII is unmasked.
    return "sha256:" + bytes.fromhex(value).hex(":")


def money(value) -> Decimal:
    try:
        amount = Decimal(str(value))
    except InvalidOperation, ValueError:
        raise ValueError("Amount must be a finite EUR number.") from None
    if isinstance(value, bool) or not amount.is_finite() or amount <= 0 or amount > Decimal("999999999.99"):
        raise ValueError("Amount must be positive and within the sandbox limit.")
    if amount != amount.quantize(Decimal("0.01")):
        raise ValueError("EUR amounts must have at most two decimal places.")
    return amount.quantize(Decimal("0.01"))


class Bank:
    def __init__(self, db):
        self.db = db
        self._sqlite_lock = asyncio.Lock()
        dialect = db.engine.dialect.name
        if dialect not in {"postgresql", "sqlite"}:
            raise ValueError("The banking sandbox requires PostgreSQL (or explicit disposable SQLite tests).")
        self.insert = pg_insert if dialect == "postgresql" else sqlite_insert

    @asynccontextmanager
    async def write_lock(self):
        # SQLite is an offline test mode. PostgreSQL uses transactional unique keys and row locks.
        if self.db.engine.dialect.name == "sqlite":
            async with self._sqlite_lock:
                yield
        else:
            yield

    async def seed(self):
        """Insert missing synthetic records, never overwrite an existing balance/profile/document."""
        async with self.db.sessionmaker() as s, s.begin():
            customers = {
                **SEED_CUSTOMERS,
                "C-LANDLORD": {
                    "name": "Synthetic landlord",
                    "address": "Sandbox beneficiary",
                    "email": "landlord@example.invalid",
                    "phone": "",
                    "iban": LANDLORD_IBAN,
                    "balance_eur": 0,
                },
            }
            for cid, profile in customers.items():
                subject = "user:jan.devries" if cid == "C-1001" else f"sandbox:{cid}"
                await s.execute(
                    self.insert(BankCustomer)
                    .values(
                        id=cid,
                        subject=subject,
                        profile={k: profile[k] for k in ("name", "address", "email", "phone")},
                    )
                    .on_conflict_do_nothing(index_elements=["id"])
                )
                await s.execute(
                    self.insert(BankAccount)
                    .values(
                        id=f"ACC-{cid}",
                        customer_id=cid,
                        iban=profile["iban"],
                        balance=Decimal(str(profile["balance_eur"])),
                    )
                    .on_conflict_do_nothing(index_elements=["id"])
                )
            for did, doc in SEED_DOCUMENTS.items():
                await s.execute(
                    self.insert(BankDocument)
                    .values(
                        id=did,
                        customer_id=doc["customer_id"],
                        kind=doc["type"],
                        text=doc["text"],
                        expires_on=date(2031, 4, 30) if did == "D-77" else None,
                    )
                    .on_conflict_do_nothing(index_elements=["id"])
                )

    @staticmethod
    async def owned(s, customer_id: str, subject: str, *, lock=False):
        query = select(BankCustomer).where(BankCustomer.id == customer_id)
        if lock:
            # Profile edits do not change keys. NO KEY UPDATE stays compatible with operation FK checks.
            query = query.with_for_update(key_share=True)
        customer = await s.scalar(query)
        if customer is None or customer.subject != subject:
            raise ValueError("Customer is not owned by the initiating user.")
        return customer

    async def balance(self, customer_id: str, actor: Execution):
        async with self.db.sessionmaker() as s:
            await self.owned(s, customer_id, actor.subject)
            account = await s.scalar(select(BankAccount).where(BankAccount.customer_id == customer_id))
            return {
                "customer_id": customer_id,
                "iban": account.iban,
                "balance_eur": float(account.balance),
                "synthetic": True,
                "storage": self.db.engine.dialect.name,
            }

    async def profile(self, customer_id: str, actor: Execution):
        async with self.db.sessionmaker() as s:
            customer = await self.owned(s, customer_id, actor.subject)
            return {"customer_id": customer_id, **customer.profile, "synthetic": True}

    async def document(self, document_id: str, actor: Execution):
        async with self.db.sessionmaker() as s:
            doc = await s.get(BankDocument, document_id)
            if doc is None:
                raise ValueError("Unknown synthetic document.")
            await self.owned(s, doc.customer_id, actor.subject)
            return doc.text

    async def operation(self, tool: str, customer_id: str, arguments: dict, actor: Execution, action):
        if not all((actor.subject, actor.root_id, actor.mandate_id, actor.agent_id)):
            raise ValueError("A gateway-authorized task is required.")
        key = digest({"root": actor.root_id, "tool": tool})
        argument_hash = digest({"customer_id": customer_id, **arguments})
        async with self.write_lock(), self.db.sessionmaker() as s, s.begin():
            await self.owned(s, customer_id, actor.subject)
            inserted = await s.scalar(
                self.insert(BankOperation)
                .values(
                    id=key,
                    root_id=actor.root_id,
                    tool=tool,
                    arguments_hash=argument_hash,
                    customer_id=customer_id,
                    result={},
                )
                .on_conflict_do_nothing(index_elements=["id"])
                .returning(BankOperation.id)
            )
            op = await s.get(BankOperation, key)
            if not inserted:
                if op.arguments_hash != argument_hash or op.customer_id != customer_id:
                    raise ValueError("This task already executed this tool with different arguments. Start a new task.")
                return {**op.result, "replayed": True}
            result = await action(s, key)
            op.result = {
                **result,
                "synthetic": True,
                "root_id": actor.root_id,
                "operation_id": key,
                "arguments_hash": argument_hash,
                "verification_hash": receipt_hash(actor.root_id, tool, argument_hash),
            }
            await ledger.append(
                s,
                "bank.operation.committed",
                actor.agent_id,
                key,
                {
                    "tool": tool,
                    "root_id": actor.root_id,
                    "mandate_id": actor.mandate_id,
                    "subject": actor.subject,
                    "arguments_hash": argument_hash,
                    "result_hash": digest(op.result),
                    "synthetic": True,
                },
            )
            await s.flush()
            return dict(op.result)

    async def transfer(self, customer_id, amount, creditor_iban, new_beneficiary, reference, actor):
        amount = money(amount)
        if not isinstance(new_beneficiary, bool) or not isinstance(reference, str) or len(reference) > 140:
            raise ValueError("Invalid beneficiary flag or payment reference (maximum 140 characters).")
        if not isinstance(creditor_iban, str) or not creditor_iban.strip():
            raise ValueError("A known synthetic beneficiary IBAN is required.")
        iban = creditor_iban.replace(" ", "").upper()

        async def apply(s, key):
            # Fixed lock order across both accounts prevents opposite transfers deadlocking.
            accounts = (
                await s.scalars(
                    select(BankAccount)
                    .where((BankAccount.customer_id == customer_id) | (BankAccount.iban == iban))
                    .order_by(BankAccount.id)
                    .with_for_update()
                )
            ).all()
            debit = next((a for a in accounts if a.customer_id == customer_id), None)
            credit = next((a for a in accounts if a.iban == iban), None)
            if debit is None or credit is None or debit.id == credit.id:
                raise ValueError(
                    "Beneficiary must be another existing synthetic sandbox account; no external settlement."
                )
            if debit.balance < amount:
                raise ValueError("Insufficient sandbox funds. No payment was created.")
            if credit.balance + amount > Decimal("9999999999999999.99"):
                raise ValueError("Beneficiary balance limit exceeded.")
            debit.balance -= amount
            credit.balance += amount
            payment_id = new_id("PAY")
            receipt = {
                "payment_id": payment_id,
                "customer_id": customer_id,
                "amount": float(amount),
                "creditor_iban": iban,
                "reference": reference,
                "status": "accepted",
                "balance_after_eur": float(debit.balance),
                "settlement": "synthetic-internal-only",
                "created_at": datetime.now(UTC).isoformat(),
                "root_id": actor.root_id,
                "synthetic": True,
            }
            s.add(
                BankPayment(
                    id=payment_id,
                    operation_id=key,
                    customer_id=customer_id,
                    debit_account=debit.id,
                    credit_account=credit.id,
                    amount=amount,
                    receipt=receipt,
                )
            )
            await s.flush()
            for account, value in ((debit, -amount), (credit, amount)):
                s.add(BankEntry(id=new_id("bke"), payment_id=payment_id, account_id=account.id, amount=value))
            return receipt

        return await self.operation(
            "payments.initiate_transfer",
            customer_id,
            {
                "amount": str(amount),
                "creditor_iban": iban,
                "new_beneficiary": new_beneficiary,
                "reference": reference,
            },
            actor,
            apply,
        )

    async def payment_status(self, payment_id: str, actor: Execution):
        async with self.db.sessionmaker() as s:
            payment = await s.get(BankPayment, payment_id)
            if payment is None:
                raise ValueError("Unknown synthetic payment.")
            await self.owned(s, payment.customer_id, actor.subject)
            return payment.receipt

    async def verify(self, customer_id: str, document_id: str, actor: Execution):
        async def apply(s, key):
            doc = await s.get(BankDocument, document_id)
            if doc is None or doc.customer_id != customer_id:
                raise ValueError("Document does not belong to this customer.")
            checks = {
                "owned_document": True,
                "supported_identity_type": doc.kind == "passport",
                "not_expired": doc.expires_on is not None and doc.expires_on >= datetime.now(UTC).date(),
            }
            return {
                "customer_id": customer_id,
                "document_id": document_id,
                "verified": all(checks.values()),
                "checks": checks,
                "verification_kind": "synthetic-record-check",
                "limitation": "No issuer validation, document authenticity or real-person identity verification.",
            }

        return await self.operation("kyc.verify_document", customer_id, {"document_id": document_id}, actor, apply)

    async def kyc_status(self, customer_id: str, actor: Execution):
        async with self.db.sessionmaker() as s:
            await self.owned(s, customer_id, actor.subject)
            op = await s.scalar(
                select(BankOperation)
                .where(BankOperation.customer_id == customer_id, BankOperation.tool == "kyc.verify_document")
                .order_by(BankOperation.created_at.desc())
                .limit(1)
            )
            return {
                "customer_id": customer_id,
                "kyc_status": "synthetic-checked" if op and op.result["verified"] else "not-verified",
                "verification_kind": "synthetic-record-check",
                "synthetic": True,
            }

    async def update_address(self, customer_id: str, new_address: str, actor: Execution):
        if not isinstance(new_address, str) or not new_address.strip() or len(new_address) > 500:
            raise ValueError("Address must be non-empty and at most 500 characters.")

        async def apply(s, key):
            verification = await s.get(BankOperation, digest({"root": actor.root_id, "tool": "kyc.verify_document"}))
            if not verification or verification.customer_id != customer_id or not verification.result.get("verified"):
                raise ValueError("A successful synthetic document check in this same task is required.")
            customer = await self.owned(s, customer_id, actor.subject, lock=True)
            customer.profile = {**customer.profile, "address": new_address}
            return {"customer_id": customer_id, "address": new_address, "status": "updated"}

        return await self.operation("crm.update_address", customer_id, {"new_address": new_address}, actor, apply)

    async def snapshot(self, subject: str):
        """Read-only, subject-bound UI view; doesn't invoke Azure or grant tool permission."""
        async with self.db.sessionmaker() as s:
            if self.db.engine.dialect.name == "postgresql":
                # Balance and payment history must come from one consistent snapshot during concurrent commits.
                await s.connection(execution_options={"isolation_level": "REPEATABLE READ"})
            customer = await s.scalar(select(BankCustomer).where(BankCustomer.subject == subject))
            if customer is None:
                raise ValueError("This user has no synthetic sandbox account.")
            account = await s.scalar(select(BankAccount).where(BankAccount.customer_id == customer.id))
            payments = (
                await s.scalars(
                    select(BankPayment)
                    .where(BankPayment.customer_id == customer.id)
                    .order_by(BankPayment.created_at.desc())
                    .limit(10)
                )
            ).all()
            return {
                "customer_id": customer.id,
                "balance_eur": float(account.balance),
                "address": customer.profile["address"],
                "beneficiary_iban": LANDLORD_IBAN,
                "payments": [p.receipt for p in payments],
                "storage": self.db.engine.dialect.name,
                "synthetic": True,
            }
