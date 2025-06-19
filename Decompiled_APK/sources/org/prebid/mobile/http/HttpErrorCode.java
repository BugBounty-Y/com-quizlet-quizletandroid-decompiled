package org.prebid.mobile.http;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class HttpErrorCode {
    public static final HttpErrorCode a;
    public static final HttpErrorCode b;
    public static final HttpErrorCode c;
    public static final HttpErrorCode d;
    public static final /* synthetic */ HttpErrorCode[] e;

    static {
        HttpErrorCode httpErrorCode = new HttpErrorCode("CONNECTION_FAILURE", 0);
        a = httpErrorCode;
        HttpErrorCode httpErrorCode2 = new HttpErrorCode("URI_SYNTAX_ERROR", 1);
        b = httpErrorCode2;
        HttpErrorCode httpErrorCode3 = new HttpErrorCode("NO_HTTP_RESPONSE", 2);
        HttpErrorCode httpErrorCode4 = new HttpErrorCode("HTTP_PROTOCOL_ERROR", 3);
        HttpErrorCode httpErrorCode5 = new HttpErrorCode("TRANSPORT_ERROR", 4);
        c = httpErrorCode5;
        HttpErrorCode httpErrorCode6 = new HttpErrorCode("UNKNOWN_ERROR", 5);
        d = httpErrorCode6;
        e = new HttpErrorCode[]{httpErrorCode, httpErrorCode2, httpErrorCode3, httpErrorCode4, httpErrorCode5, httpErrorCode6};
    }

    public static HttpErrorCode valueOf(String str) {
        return (HttpErrorCode) Enum.valueOf(HttpErrorCode.class, str);
    }

    public static HttpErrorCode[] values() {
        return (HttpErrorCode[]) e.clone();
    }
}
