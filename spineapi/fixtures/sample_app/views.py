from ratelimit.decorators import ratelimit
from rest_framework.throttling import UserRateThrottle

throttle_classes = [UserRateThrottle]

@ratelimit(key="ip", rate="5/m", method="POST")
def login(request):
    return None

def me(request):
    return None

def debug(request):
    return None
