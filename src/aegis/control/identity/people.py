"""One real person, several accounts: separation of duties must compare people, not usernames (plan §8.14).

A person who acts in several roles holds one account per role. Every account is tied to a person id, from (in order)
the trusted `person_links` directory, the sign-in token's person claim, or the account name when nothing links it.
Each sign-in records its account -> person mapping, so a check can also resolve a name that is only stored on a record
(an agent's owner, a policy's author) and may not be signed in right now.
"""

import asyncio
import logging

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.control.identity.idp import DevIdp, Persona
from aegis.control.tables import PersonLink

log = logging.getLogger("aegis.control.people")


def fold(value: str) -> str:
    return value.strip().casefold()


class PersonDirectory:
    def __init__(self, links: dict[str, str], idp: DevIdp | None = None, db=None):
        self._links = {fold(k): fold(v) for k, v in links.items() if k.strip() and v.strip()}
        self._idp = idp
        self._db = db
        self._recorded: dict[str, str] = {}
        self._lock = asyncio.Lock()

    def has_link(self, username: str) -> bool:
        return fold(username) in self._links

    def person_of(self, persona: Persona) -> str:
        """The person behind a signed-in account: configured link, else the account's own person id, else its name."""
        return self._links.get(fold(persona.username)) or fold(persona.person_id or persona.username)

    async def _upsert(self, name: str, person: str) -> None:
        async with self._db.sessionmaker() as s:
            row = await s.get(PersonLink, name)
            if row is None:
                s.add(PersonLink(username=name, person_id=person))
            elif row.person_id != person:
                row.person_id = person
            await s.commit()

    async def record(self, persona: Persona) -> None:
        """Remember account -> person. A storage failure is logged and retried at the next sign-in, never fatal."""
        if self._db is None:
            return
        name, person = fold(persona.username), self.person_of(persona)
        if self._recorded.get(name) == person:
            return
        # A console sends several requests at once with one token: the first sign-in must not race itself.
        async with self._lock:
            if self._recorded.get(name) == person:
                return
            try:
                try:
                    await self._upsert(name, person)
                except IntegrityError:  # another worker inserted this account first: update its row instead
                    await self._upsert(name, person)
            except SQLAlchemyError as exc:
                log.warning("could not record the person behind account %r: %s", persona.username, type(exc).__name__)
                return
            self._recorded[name] = person

    async def person_of_name(self, s: AsyncSession, username: str) -> str:
        """The person behind an account name stored on a record, whether or not that account is signed in."""
        name = fold(username)
        if name in self._links:
            return self._links[name]
        known = next((p for n, p in self._idp.personas.items() if fold(n) == name), None) if self._idp else None
        if known is not None and known.person_id:
            return fold(known.person_id)
        row = await s.get(PersonLink, name)
        return row.person_id if row is not None else name

    async def same_people(self, s: AsyncSession, first: str, second: str) -> bool:
        """Do two account names stored on records belong to one person?"""
        if not first.strip() or not second.strip():
            return False
        return await self.person_of_name(s, first) == await self.person_of_name(s, second)

    def has_left(self, username: str) -> bool:
        """True when the development IdP knows this account and it is no longer active (an owner who left)."""
        name = fold(username)
        known = next((p for n, p in self._idp.personas.items() if fold(n) == name), None) if self._idp else None
        return known is not None and known.status != "active"

    async def same_person(self, s: AsyncSession, user: Persona, username: str | None) -> bool:
        """Is the signed-in user the person behind `username`, under whichever account? False for a blank name."""
        if not username or not username.strip():
            return False
        return self.person_of(user) == await self.person_of_name(s, username)
