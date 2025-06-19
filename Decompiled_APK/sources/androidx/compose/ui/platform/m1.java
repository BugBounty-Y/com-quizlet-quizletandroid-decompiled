package androidx.compose.ui.platform;

import android.view.View;
import androidx.compose.runtime.C0799h0;
import androidx.compose.runtime.C0832v0;
import java.util.ArrayList;
import kotlin.Unit;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.InterfaceC5026k;

/* loaded from: classes.dex */
public final class m1 implements androidx.lifecycle.H {
    public final /* synthetic */ kotlinx.coroutines.internal.d a;
    public final /* synthetic */ C0799h0 b;
    public final /* synthetic */ C0832v0 c;
    public final /* synthetic */ kotlin.jvm.internal.J d;
    public final /* synthetic */ View e;

    public m1(kotlinx.coroutines.internal.d dVar, C0799h0 c0799h0, C0832v0 c0832v0, kotlin.jvm.internal.J j, View view) {
        this.a = dVar;
        this.b = c0799h0;
        this.c = c0832v0;
        this.d = j;
        this.e = view;
    }

    @Override // androidx.lifecycle.H
    public final void d(androidx.lifecycle.J j, androidx.lifecycle.A a) {
        boolean z;
        int i = j1.a[a.ordinal()];
        InterfaceC5026k interfaceC5026kY = null;
        if (i == 1) {
            kotlinx.coroutines.E.A(this.a, null, kotlinx.coroutines.D.d, new l1(this.d, this.c, j, this, this.e, null), 1);
            return;
        }
        if (i != 2) {
            if (i != 3) {
                if (i != 4) {
                    return;
                }
                this.c.w();
                return;
            } else {
                C0832v0 c0832v0 = this.c;
                synchronized (c0832v0.c) {
                    c0832v0.t = true;
                    Unit unit = Unit.a;
                }
                return;
            }
        }
        C0799h0 c0799h0 = this.b;
        if (c0799h0 != null) {
            androidx.browser.customtabs.k kVar = c0799h0.b;
            synchronized (kVar.b) {
                try {
                    synchronized (kVar.b) {
                        z = kVar.a;
                    }
                    if (!z) {
                        ArrayList arrayList = (ArrayList) kVar.c;
                        kVar.c = (ArrayList) kVar.d;
                        kVar.d = arrayList;
                        kVar.a = true;
                        int size = arrayList.size();
                        for (int i2 = 0; i2 < size; i2++) {
                            kotlin.coroutines.h hVar = (kotlin.coroutines.h) arrayList.get(i2);
                            kotlin.p pVar = kotlin.r.b;
                            hVar.resumeWith(Unit.a);
                        }
                        arrayList.clear();
                        Unit unit2 = Unit.a;
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
        C0832v0 c0832v02 = this.c;
        synchronized (c0832v02.c) {
            if (c0832v02.t) {
                c0832v02.t = false;
                interfaceC5026kY = c0832v02.y();
            }
        }
        if (interfaceC5026kY != null) {
            kotlin.p pVar2 = kotlin.r.b;
            ((C5028l) interfaceC5026kY).resumeWith(Unit.a);
        }
    }
}
