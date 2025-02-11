"""
Allows modules to register functions (callables) to be run at
specified times or intervals (like cron does).

Based on APScheduler package
"""

import logging
from typing import Callable, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger


class Scheduler():
    """
    Allows modules to register functions (callables) to be run
    at specified times or intervals (like cron does).
    """

    def __init__(self) -> None:
        self.log = logging.getLogger("Scheduler")
        # self.log.setLevel("DEBUG")
        logging.getLogger("apscheduler.scheduler").setLevel("WARNING")
        logging.getLogger("apscheduler.executors.default").setLevel("WARNING")
        self.sched = BackgroundScheduler(timezone="UTC")
        self.last_job_id = 0

    def start(self) -> None:
        self.log.debug("Scheduler start")
        self.sched.start()

    def stop(self) -> None:
        self.log.debug("Scheduler stop")
        self.sched.shutdown()

    def register(self, func: Callable, year: None = None, month: None = None, day: None = None, week: None = None,
                 day_of_week: None = None, hour: None = None, minute: Optional[str] = None,
                 second: Optional[str] = None, timezone: str = "UTC",
                 args: None = None, kwargs: None = None) -> int:
        """
        Register a function to be run at specified times.

        func - function or method to be called
        year,month,day,week,day_of_week,hour,minute,second -
           cron-like specification of when the function should be called,
           see docs of apscheduler.triggers.cron for details
           https://apscheduler.readthedocs.io/en/latest/modules/triggers/cron.html
        timezone - Timezone for time specification (default is UTC).
        args, kwargs - arguments passed to func

        Return job ID (integer).
        """
        self.last_job_id += 1
        trigger = CronTrigger(year, month, day, week, day_of_week, hour, minute,
                              second, timezone=timezone)
        self.sched.add_job(func, trigger, args, kwargs, coalesce=True, max_instances=1, id=str(self.last_job_id))
        self.log.debug("Registered function {0} to be called at {1}".format(func.__qualname__, trigger))
        return self.last_job_id

    def pause_job(self, id):
        """Pause job with given ID"""
        self.sched.pause_job(str(id))

    def resume_job(self, id):
        """Resume previously paused job with given ID"""
        self.sched.resume_job(str(id))

