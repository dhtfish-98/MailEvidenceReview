"""Local immutable EML structural evidence; no mail-client or authenticity verdict."""
__version__='0.1.0'
from .api import review
from .contracts import Limits
__all__=['review','Limits','__version__']
