package com.facebook;

import android.content.Intent;
import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class i {
    public final int a;
    public final int b;
    public final Intent c;

    public i(int i, int i2, Intent intent) {
        this.a = i;
        this.b = i2;
        this.c = intent;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a == iVar.a && this.b == iVar.b && Intrinsics.b(this.c, iVar.c);
    }

    public final int hashCode() {
        int iB = d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
        Intent intent = this.c;
        return iB + (intent == null ? 0 : intent.hashCode());
    }

    public final String toString() {
        return "ActivityResultParameters(requestCode=" + this.a + ", resultCode=" + this.b + ", data=" + this.c + ')';
    }
}
