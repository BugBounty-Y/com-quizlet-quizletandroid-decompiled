package io.ktor.util;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final String a;
    public final int b;

    public d(String content) {
        Intrinsics.checkNotNullParameter(content, "content");
        this.a = content;
        int length = content.length();
        int lowerCase = 0;
        for (int i = 0; i < length; i++) {
            lowerCase = (lowerCase * 31) + Character.toLowerCase(content.charAt(i));
        }
        this.b = lowerCase;
    }

    public final boolean equals(Object obj) {
        String str;
        d dVar = obj instanceof d ? (d) obj : null;
        return (dVar == null || (str = dVar.a) == null || !str.equalsIgnoreCase(this.a)) ? false : true;
    }

    public final int hashCode() {
        return this.b;
    }

    public final String toString() {
        return this.a;
    }
}
