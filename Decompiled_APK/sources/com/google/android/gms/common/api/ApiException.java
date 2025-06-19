package com.google.android.gms.common.api;

/* loaded from: classes2.dex */
public class ApiException extends Exception {
    public final Status a;

    public ApiException(Status status) {
        int i = status.a;
        String str = status.b;
        str = str == null ? "" : str;
        StringBuilder sb = new StringBuilder(String.valueOf(i).length() + 2 + String.valueOf(str).length());
        sb.append(i);
        sb.append(": ");
        sb.append(str);
        super(sb.toString());
        this.a = status;
    }
}
