package androidx.compose.foundation.text;

import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.text.f0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0488f0 {
    public static final C0488f0 g = new C0488f0((Function1) null, (Function1) null, (Function1) null, (Function1) null, (Function1) null, 63);
    public final Function1 a;
    public final Function1 b;
    public final Function1 c;
    public final Function1 d;
    public final Function1 e;
    public final Function1 f;

    public C0488f0(Function1 function1, Function1 function12, Function1 function13, Function1 function14, Function1 function15, Function1 function16) {
        this.a = function1;
        this.b = function12;
        this.c = function13;
        this.d = function14;
        this.e = function15;
        this.f = function16;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0488f0)) {
            return false;
        }
        C0488f0 c0488f0 = (C0488f0) obj;
        return this.a == c0488f0.a && this.b == c0488f0.b && this.c == c0488f0.c && this.d == c0488f0.d && this.e == c0488f0.e && this.f == c0488f0.f;
    }

    public final int hashCode() {
        Function1 function1 = this.a;
        int iHashCode = (function1 != null ? function1.hashCode() : 0) * 31;
        Function1 function12 = this.b;
        int iHashCode2 = (iHashCode + (function12 != null ? function12.hashCode() : 0)) * 31;
        Function1 function13 = this.c;
        int iHashCode3 = (iHashCode2 + (function13 != null ? function13.hashCode() : 0)) * 31;
        Function1 function14 = this.d;
        int iHashCode4 = (iHashCode3 + (function14 != null ? function14.hashCode() : 0)) * 31;
        Function1 function15 = this.e;
        int iHashCode5 = (iHashCode4 + (function15 != null ? function15.hashCode() : 0)) * 31;
        Function1 function16 = this.f;
        return iHashCode5 + (function16 != null ? function16.hashCode() : 0);
    }

    public /* synthetic */ C0488f0(Function1 function1, Function1 function12, Function1 function13, Function1 function14, Function1 function15, int i) {
        this((i & 1) != 0 ? null : function1, (i & 2) != 0 ? null : function12, (i & 4) != 0 ? null : function13, (Function1) null, (i & 16) != 0 ? null : function14, (i & 32) != 0 ? null : function15);
    }
}
