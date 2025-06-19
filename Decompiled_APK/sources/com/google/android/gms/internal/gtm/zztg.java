package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;

/* loaded from: classes2.dex */
abstract class zztg {
    public static void zza(Object obj, Object obj2) {
        if (obj == null) {
            throw new NullPointerException("null key in entry: null=".concat(String.valueOf(obj2)));
        }
        if (obj2 == null) {
            throw new NullPointerException(a.B("null value in entry: ", obj.toString(), "=null"));
        }
    }
}
