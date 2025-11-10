import logging
import queue
import time
import typing

from sqlalchemy import and_

from empire.server.common.helpers import KThread
from empire.server.common.socks import create_client, start_client
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu

log = logging.getLogger(__name__)


class AgentSocksService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

        self._socksthreads = {}
        self._socksqueues = {}
        self._socksclients = {}

        self._start_existing_socks()

    def _start_existing_socks(self):
        with SessionLocal.begin() as db:
            agents = (
                db.query(models.Agent)
                .filter(
                    and_(
                        models.Agent.socks == True,  # noqa: E712
                        models.Agent.archived == False,  # noqa: E712
                    )
                )
                .all()
            )
            for agent in agents:
                self.start_socks_client(agent)

    def start_socks_client(self, agent: models.Agent):
        session_id = agent.session_id
        if session_id not in self._socksthreads:
            try:
                log.info(f"Starting SOCKS client for {session_id}")
                self._socksqueues[session_id] = queue.Queue()
                client = create_client(
                    self.main_menu, self._socksqueues[session_id], session_id
                )
                self._socksthreads[session_id] = KThread(
                    target=start_client,
                    args=(client, agent.socks_port),
                )

                self._socksclients[session_id] = client
                self._socksthreads[session_id].daemon = True
                self._socksthreads[session_id].start()
                log.info(f'SOCKS client for "{agent.name}" successfully started')
            except Exception:
                log.error(f'SOCKS client for "{agent.name}" failed to started')
        else:
            log.info("SOCKS server already exists")

    def queue_socks_data(self, agent: models.Agent, data: bytes):
        if agent.session_id in self._socksthreads:
            self._socksqueues[agent.session_id].put(data)

    def close_socks_client(self, agent: models.Agent):
        if agent.session_id in self._socksthreads:
            agent.socks = False
            self._socksclients[agent.session_id].shutdown()
            time.sleep(1)
            self._socksthreads[agent.session_id].kill()
