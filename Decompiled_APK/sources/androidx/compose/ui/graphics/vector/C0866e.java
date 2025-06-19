package androidx.compose.ui.graphics.vector;

import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.X;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* renamed from: androidx.compose.ui.graphics.vector.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0866e {
    public final String a;
    public final float b;
    public final float c;
    public final float d;
    public final float e;
    public final long f;
    public final int g;
    public final boolean h;
    public final ArrayList i;
    public final C0865d j;
    public boolean k;

    public C0866e(String str, float f, float f2, float f3, float f4, long j, int i, boolean z, int i2) {
        str = (i2 & 1) != 0 ? "" : str;
        long j2 = (i2 & 32) != 0 ? C0861v.g : j;
        int i3 = (i2 & 64) != 0 ? 5 : i;
        this.a = str;
        this.b = f;
        this.c = f2;
        this.d = f3;
        this.e = f4;
        this.f = j2;
        this.g = i3;
        this.h = z;
        ArrayList arrayList = new ArrayList();
        this.i = arrayList;
        C0865d c0865d = new C0865d(null, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, 1023);
        this.j = c0865d;
        arrayList.add(c0865d);
    }

    public static void a(C0866e c0866e, ArrayList arrayList, X x) {
        if (c0866e.k) {
            W4.f("ImageVector.Builder is single use, create a new instance to create a new ImageVector");
            throw null;
        }
        ((C0865d) android.support.v4.media.session.a.e(1, c0866e.i)).j.add(new L("", arrayList, 0, x, 1.0f, null, 1.0f, 1.0f, 0, 2, 1.0f, DefinitionKt.NO_Float_VALUE, 1.0f, DefinitionKt.NO_Float_VALUE));
    }

    public final C0867f b() {
        if (this.k) {
            W4.f("ImageVector.Builder is single use, create a new instance to create a new ImageVector");
            throw null;
        }
        while (true) {
            ArrayList arrayList = this.i;
            if (arrayList.size() <= 1) {
                C0865d c0865d = this.j;
                C0867f c0867f = new C0867f(this.a, this.b, this.c, this.d, this.e, new H(c0865d.a, c0865d.b, c0865d.c, c0865d.d, c0865d.e, c0865d.f, c0865d.g, c0865d.h, c0865d.i, c0865d.j), this.f, this.g, this.h);
                this.k = true;
                return c0867f;
            }
            if (this.k) {
                W4.f("ImageVector.Builder is single use, create a new instance to create a new ImageVector");
                throw null;
            }
            C0865d c0865d2 = (C0865d) arrayList.remove(arrayList.size() - 1);
            ((C0865d) android.support.v4.media.session.a.e(1, arrayList)).j.add(new H(c0865d2.a, c0865d2.b, c0865d2.c, c0865d2.d, c0865d2.e, c0865d2.f, c0865d2.g, c0865d2.h, c0865d2.i, c0865d2.j));
        }
    }
}
