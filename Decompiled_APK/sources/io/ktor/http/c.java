package io.ktor.http;

import kotlin.collections.K;

/* loaded from: classes3.dex */
public abstract class c {
    public static final d a;

    static {
        K k = K.a;
        new d("text", "*", k);
        a = new d("text", "plain", k);
        new d("text", "css", k);
        new d("text", "csv", k);
        new d("text", "html", k);
        new d("text", "javascript", k);
        new d("text", "vcard", k);
        new d("text", "xml", k);
        new d("text", "event-stream", k);
    }
}
