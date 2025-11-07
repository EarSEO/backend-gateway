package com.earseo.backendgateway.common.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum AuthError implements ErrorCodeInterface{
    EXPIRED_TOKEN("AUTH_001", "토큰이 만료되었습니다.", HttpStatus.BAD_REQUEST),
    INVALID_TOKEN("AUTH_002", "유효하지 않은 토큰입니다.", HttpStatus.BAD_REQUEST),
    UNSUPPORTED_JWT("AUTH_003", "지원하지 않는 토큰입니다.", HttpStatus.BAD_REQUEST),
    ;

    private final String status;
    private final String message;
    private final HttpStatus httpStatus;

    @Override
    public ErrorCode getErrorCode() {
        return ErrorCode.builder()
                .status(status)
                .message(message)
                .httpStatus(httpStatus)
                .build();
    }
}
