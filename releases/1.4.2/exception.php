<?php
/*
 * PHP Rate Limiting Library v.1.4.2
 * PHP Version ^7.4
 *
 * Copyright 2021 TBM Productions
 * https://tbmproduction.com/license
 *
 * https://developer.tbmproduction.com/docs/ratelimit
 */

namespace RateLimit;

/*
 * @info Bring standard Exception class into Namespace
 */

class Exception extends \Exception {};

/*
 * @info Extend Exception class with RateLimitBuildException
 * @info Significes an error while constructing or setting up the enviroment
 */

final class RateLimitBuildException extends Exception {};

/*
 * @info Extend Exception class with RateLimitException
 * @info Generalised Exception; All other errors fall to this
 */

final class RateLimitException extends Exception {};