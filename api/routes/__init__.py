# api/routes/__init__.py - Label the toys so robot finds 'em easy!
from .auth import router as auth
from .scan import router as scan
from .soc import router as soc
from .siem import router as siem
from .reports import router as reports
from .tenants import router as tenants

__all__ = ['auth', 'scan', 'soc', 'siem', 'reports', 'tenants']