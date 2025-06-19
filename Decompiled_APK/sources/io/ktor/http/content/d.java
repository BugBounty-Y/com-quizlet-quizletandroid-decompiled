package io.ktor.http.content;

import kotlin.text.I;

/* loaded from: classes3.dex */
public final class d extends b {
    public final String a;
    public final io.ktor.http.d b;
    public final byte[] c;

    /* JADX WARN: Removed duplicated region for block: B:14:0x0077  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public d(java.lang.String r5, io.ktor.http.d r6) throws java.nio.charset.CharacterCodingException {
        /*
            r4 = this;
            java.lang.String r0 = "text"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
            java.lang.String r0 = "contentType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            r4.<init>()
            r4.a = r5
            r4.b = r6
            java.nio.charset.Charset r6 = com.google.android.gms.internal.mlkit_vision_barcode.X6.b(r6)
            if (r6 != 0) goto L19
            java.nio.charset.Charset r6 = kotlin.text.Charsets.UTF_8
        L19:
            java.lang.String r0 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
            java.lang.String r1 = "charset"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r1)
            java.nio.charset.Charset r1 = kotlin.text.Charsets.UTF_8
            boolean r2 = kotlin.jvm.internal.Intrinsics.b(r6, r1)
            r3 = 0
            if (r2 == 0) goto L82
            int r6 = r5.length()
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
            kotlin.collections.d r0 = kotlin.collections.AbstractC4916g.a
            int r2 = r5.length()
            r0.getClass()
            kotlin.collections.C4913d.a(r3, r6, r2)
            java.nio.charset.CharsetEncoder r0 = r1.newEncoder()
            java.nio.charset.CodingErrorAction r1 = java.nio.charset.CodingErrorAction.REPORT
            java.nio.charset.CharsetEncoder r0 = r0.onMalformedInput(r1)
            java.nio.charset.CharsetEncoder r0 = r0.onUnmappableCharacter(r1)
            java.nio.CharBuffer r5 = java.nio.CharBuffer.wrap(r5, r3, r6)
            java.nio.ByteBuffer r5 = r0.encode(r5)
            boolean r6 = r5.hasArray()
            if (r6 == 0) goto L77
            int r6 = r5.arrayOffset()
            if (r6 != 0) goto L77
            int r6 = r5.remaining()
            byte[] r0 = r5.array()
            kotlin.jvm.internal.Intrinsics.d(r0)
            int r0 = r0.length
            if (r6 != r0) goto L77
            byte[] r5 = r5.array()
            kotlin.jvm.internal.Intrinsics.d(r5)
            goto L8e
        L77:
            int r6 = r5.remaining()
            byte[] r6 = new byte[r6]
            r5.get(r6)
            r5 = r6
            goto L8e
        L82:
            java.nio.charset.CharsetEncoder r6 = r6.newEncoder()
            int r0 = r5.length()
            byte[] r5 = com.google.android.gms.internal.mlkit_vision_barcode.s7.c(r6, r5, r3, r0)
        L8e:
            r4.c = r5
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.http.content.d.<init>(java.lang.String, io.ktor.http.d):void");
    }

    @Override // io.ktor.http.content.c
    public final Long a() {
        return Long.valueOf(this.c.length);
    }

    @Override // io.ktor.http.content.c
    public final io.ktor.http.d b() {
        return this.b;
    }

    @Override // io.ktor.http.content.b
    public final byte[] d() {
        return this.c;
    }

    public final String toString() {
        return "TextContent[" + this.b + "] \"" + I.C(30, this.a) + '\"';
    }
}
