package com.bumptech.glide.load;

import java.io.IOException;

/* loaded from: classes.dex */
public final class HttpException extends IOException {
    public HttpException(String str, int i, IOException iOException) {
        super(str + ", status code: " + i, iOException);
    }
}
