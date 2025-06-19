package androidx.compose.ui.graphics;

import android.os.Build;
import androidx.compose.ui.platform.C0971v;
import kotlin.Unit;

/* renamed from: androidx.compose.ui.graphics.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0847g implements E {
    public static boolean d = true;
    public final C0971v a;
    public final Object b = new Object();
    public androidx.compose.ui.graphics.layer.view.b c;

    public C0847g(C0971v c0971v) {
        this.a = c0971v;
    }

    @Override // androidx.compose.ui.graphics.E
    public final void a(androidx.compose.ui.graphics.layer.b bVar) {
        synchronized (this.b) {
            if (!bVar.r) {
                bVar.r = true;
                bVar.b();
            }
            Unit unit = Unit.a;
        }
    }

    @Override // androidx.compose.ui.graphics.E
    public final androidx.compose.ui.graphics.layer.b b() {
        androidx.compose.ui.graphics.layer.d iVar;
        androidx.compose.ui.graphics.layer.b bVar;
        synchronized (this.b) {
            try {
                C0971v c0971v = this.a;
                int i = Build.VERSION.SDK_INT;
                if (i >= 29) {
                    AbstractC0846f.a(c0971v);
                }
                if (i >= 29) {
                    iVar = new androidx.compose.ui.graphics.layer.g();
                } else if (d) {
                    try {
                        iVar = new androidx.compose.ui.graphics.layer.e(this.a, new C0859t(), new androidx.compose.ui.graphics.drawscope.b());
                    } catch (Throwable unused) {
                        d = false;
                        C0971v c0971v2 = this.a;
                        androidx.compose.ui.graphics.layer.view.b bVar2 = this.c;
                        if (bVar2 == null) {
                            androidx.compose.ui.graphics.layer.view.b bVar3 = new androidx.compose.ui.graphics.layer.view.b(c0971v2.getContext());
                            c0971v2.addView(bVar3, -1);
                            this.c = bVar3;
                            bVar2 = bVar3;
                        }
                        iVar = new androidx.compose.ui.graphics.layer.i(bVar2);
                    }
                } else {
                    C0971v c0971v3 = this.a;
                    androidx.compose.ui.graphics.layer.view.b bVar4 = this.c;
                    if (bVar4 == null) {
                        androidx.compose.ui.graphics.layer.view.b bVar5 = new androidx.compose.ui.graphics.layer.view.b(c0971v3.getContext());
                        c0971v3.addView(bVar5, -1);
                        this.c = bVar5;
                        bVar4 = bVar5;
                    }
                    iVar = new androidx.compose.ui.graphics.layer.i(bVar4);
                }
                bVar = new androidx.compose.ui.graphics.layer.b(iVar);
            } catch (Throwable th) {
                throw th;
            }
        }
        return bVar;
    }
}
