package com.facebook;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class FacebookRequestError implements Parcelable {
    public final int a;
    public final int b;
    public final int c;
    public final String d;
    public final String e;
    public final String f;
    public final Object g;
    public final String h;
    public final FacebookException i;
    public static final retrofit2.adapter.rxjava3.d j = new retrofit2.adapter.rxjava3.d(7);

    @NotNull
    public static final Parcelable.Creator<FacebookRequestError> CREATOR = new android.support.v4.media.a(13);

    /* JADX WARN: Removed duplicated region for block: B:7:0x002e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public FacebookRequestError(int r1, int r2, int r3, java.lang.String r4, java.lang.String r5, java.lang.String r6, java.lang.String r7, java.lang.Object r8, com.facebook.FacebookException r9, boolean r10) {
        /*
            r0 = this;
            r0.<init>()
            r0.a = r1
            r0.b = r2
            r0.c = r3
            r0.d = r4
            r0.e = r6
            r0.f = r7
            r0.g = r8
            r0.h = r5
            retrofit2.adapter.rxjava3.d r1 = com.facebook.FacebookRequestError.j
            r4 = 2
            if (r9 == 0) goto L1c
            r0.i = r9
            goto La1
        L1c:
            com.facebook.FacebookServiceException r5 = new com.facebook.FacebookServiceException
            java.lang.String r6 = r0.a()
            r5.<init>(r0, r6)
            r0.i = r5
            com.facebook.internal.m r5 = r1.r()
            r6 = 3
            if (r10 == 0) goto L31
        L2e:
            r4 = r6
            goto La1
        L31:
            java.util.HashMap r7 = r5.a
            if (r7 == 0) goto L56
            java.lang.Integer r8 = java.lang.Integer.valueOf(r2)
            boolean r8 = r7.containsKey(r8)
            if (r8 == 0) goto L56
            java.lang.Integer r8 = java.lang.Integer.valueOf(r2)
            java.lang.Object r7 = r7.get(r8)
            java.util.Set r7 = (java.util.Set) r7
            if (r7 == 0) goto La1
            java.lang.Integer r8 = java.lang.Integer.valueOf(r3)
            boolean r7 = r7.contains(r8)
            if (r7 == 0) goto L56
            goto La1
        L56:
            java.util.HashMap r7 = r5.c
            if (r7 == 0) goto L7c
            java.lang.Integer r8 = java.lang.Integer.valueOf(r2)
            boolean r8 = r7.containsKey(r8)
            if (r8 == 0) goto L7c
            java.lang.Integer r8 = java.lang.Integer.valueOf(r2)
            java.lang.Object r7 = r7.get(r8)
            java.util.Set r7 = (java.util.Set) r7
            if (r7 == 0) goto L7a
            java.lang.Integer r8 = java.lang.Integer.valueOf(r3)
            boolean r7 = r7.contains(r8)
            if (r7 == 0) goto L7c
        L7a:
            r4 = 1
            goto La1
        L7c:
            java.util.HashMap r5 = r5.b
            if (r5 == 0) goto La1
            java.lang.Integer r7 = java.lang.Integer.valueOf(r2)
            boolean r7 = r5.containsKey(r7)
            if (r7 == 0) goto La1
            java.lang.Integer r2 = java.lang.Integer.valueOf(r2)
            java.lang.Object r2 = r5.get(r2)
            java.util.Set r2 = (java.util.Set) r2
            if (r2 == 0) goto L2e
            java.lang.Integer r3 = java.lang.Integer.valueOf(r3)
            boolean r2 = r2.contains(r3)
            if (r2 == 0) goto La1
            goto L2e
        La1:
            r1.r()
            int[] r1 = com.facebook.internal.AbstractC1557l.a
            int r2 = androidx.camera.camera2.internal.AbstractC0147y.k(r4)
            r1 = r1[r2]
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.FacebookRequestError.<init>(int, int, int, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.Object, com.facebook.FacebookException, boolean):void");
    }

    public final String a() {
        String str = this.h;
        if (str != null) {
            return str;
        }
        FacebookException facebookException = this.i;
        if (facebookException != null) {
            return facebookException.getLocalizedMessage();
        }
        return null;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final String toString() {
        String str = "{HttpStatus: " + this.a + ", errorCode: " + this.b + ", subErrorCode: " + this.c + ", errorType: " + this.d + ", errorMessage: " + a() + "}";
        Intrinsics.checkNotNullExpressionValue(str, "StringBuilder(\"{HttpStat…(\"}\")\n        .toString()");
        return str;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel out, int i) {
        Intrinsics.checkNotNullParameter(out, "out");
        out.writeInt(this.a);
        out.writeInt(this.b);
        out.writeInt(this.c);
        out.writeString(this.d);
        out.writeString(a());
        out.writeString(this.e);
        out.writeString(this.f);
    }

    public FacebookRequestError(Exception exc) {
        this(-1, -1, -1, null, null, null, null, null, exc instanceof FacebookException ? (FacebookException) exc : new FacebookException(exc), false);
    }

    public FacebookRequestError(int i, String str, String str2) {
        this(-1, i, -1, str, str2, null, null, null, null, false);
    }
}
