"""Durable synthetic banking records. These are not external settlement or issuer-verified identity."""

from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import JSON, CheckConstraint, Date, DateTime, ForeignKey, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aegis.control.tables import Base, utcnow


class BankCustomer(Base):
    __tablename__ = "bank_customers"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    subject: Mapped[str] = mapped_column(String(120), unique=True)
    profile: Mapped[dict] = mapped_column(JSON)


class BankAccount(Base):
    __tablename__ = "bank_accounts"
    __table_args__ = (CheckConstraint("balance >= 0", name="bank_balance_nonnegative"),)
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("bank_customers.id"), unique=True)
    iban: Mapped[str] = mapped_column(String(34), unique=True)
    balance: Mapped[Decimal] = mapped_column(Numeric(18, 2))


class BankDocument(Base):
    __tablename__ = "bank_documents"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("bank_customers.id"))
    kind: Mapped[str] = mapped_column(String(40))
    expires_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    text: Mapped[str] = mapped_column(Text)


class BankOperation(Base):
    """One committed result per root task/tool. Unique insertion serializes duplicate requests."""

    __tablename__ = "bank_operations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    root_id: Mapped[str] = mapped_column(String(40), index=True)
    tool: Mapped[str] = mapped_column(String(130))
    arguments_hash: Mapped[str] = mapped_column(String(64))
    customer_id: Mapped[str] = mapped_column(ForeignKey("bank_customers.id"))
    result: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BankPayment(Base):
    __tablename__ = "bank_payments"
    __table_args__ = (CheckConstraint("amount > 0", name="bank_payment_positive"),)
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    operation_id: Mapped[str] = mapped_column(ForeignKey("bank_operations.id"), unique=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("bank_customers.id"), index=True)
    debit_account: Mapped[str] = mapped_column(ForeignKey("bank_accounts.id"))
    credit_account: Mapped[str] = mapped_column(ForeignKey("bank_accounts.id"))
    amount: Mapped[Decimal] = mapped_column(Numeric(18, 2))
    receipt: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BankEntry(Base):
    __tablename__ = "bank_entries"
    __table_args__ = (CheckConstraint("amount <> 0", name="bank_entry_nonzero"),)
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    payment_id: Mapped[str] = mapped_column(ForeignKey("bank_payments.id"), index=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("bank_accounts.id"), index=True)
    amount: Mapped[Decimal] = mapped_column(Numeric(18, 2))


class RegistrySeedArchive(Base):
    __tablename__ = "registry_seed_archive"
    agent_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    batch_id: Mapped[str] = mapped_column(String(40), primary_key=True, index=True)
    snapshot: Mapped[dict] = mapped_column(JSON)
    archived_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
