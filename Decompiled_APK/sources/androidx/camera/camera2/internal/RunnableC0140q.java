package androidx.camera.camera2.internal;

import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0168g;
import androidx.camera.core.impl.x0;
import java.util.ArrayList;
import java.util.LinkedHashMap;

/* renamed from: androidx.camera.camera2.internal.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC0140q implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C b;
    public final /* synthetic */ String c;
    public final /* synthetic */ androidx.camera.core.impl.q0 d;
    public final /* synthetic */ A0 e;
    public final /* synthetic */ C0168g f;
    public final /* synthetic */ ArrayList g;

    public /* synthetic */ RunnableC0140q(C c, String str, androidx.camera.core.impl.q0 q0Var, A0 a0, C0168g c0168g, ArrayList arrayList, int i) {
        this.a = i;
        this.b = c;
        this.c = str;
        this.d = q0Var;
        this.e = a0;
        this.f = c0168g;
        this.g = arrayList;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C c = this.b;
                c.getClass();
                StringBuilder sb = new StringBuilder("Use case ");
                String str = this.c;
                sb.append(str);
                sb.append(" ACTIVE");
                c.t(sb.toString());
                LinkedHashMap linkedHashMap = c.a.a;
                x0 x0Var = (x0) linkedHashMap.get(str);
                androidx.camera.core.impl.q0 q0Var = this.d;
                A0 a0 = this.e;
                C0168g c0168g = this.f;
                ArrayList arrayList = this.g;
                if (x0Var == null) {
                    x0Var = new x0(q0Var, a0, c0168g, arrayList);
                    linkedHashMap.put(str, x0Var);
                }
                x0Var.f = true;
                c.a.i(str, q0Var, a0, c0168g, arrayList);
                c.K();
                break;
            default:
                C c2 = this.b;
                c2.getClass();
                StringBuilder sb2 = new StringBuilder("Use case ");
                String str2 = this.c;
                sb2.append(str2);
                sb2.append(" UPDATED");
                c2.t(sb2.toString());
                c2.a.i(str2, this.d, this.e, this.f, this.g);
                c2.K();
                break;
        }
    }
}
