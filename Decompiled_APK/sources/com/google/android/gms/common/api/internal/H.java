package com.google.android.gms.common.api.internal;

import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.widget.C0122z;
import androidx.fragment.app.Fragment;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.Iterator;
import java.util.Map;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class H extends Fragment implements InterfaceC1649g {
    public static final WeakHashMap b = new WeakHashMap();
    public final C0122z a = new C0122z(11, (byte) 0);

    @Override // com.google.android.gms.common.api.internal.InterfaceC1649g
    public final l b() {
        return (l) l.class.cast(((Map) this.a.c).get("ConnectionlessLifecycleHelper"));
    }

    @Override // androidx.fragment.app.Fragment
    public final void dump(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        super.dump(str, fileDescriptor, printWriter, strArr);
        Iterator it2 = ((Map) this.a.c).values().iterator();
        while (it2.hasNext()) {
            ((l) it2.next()).getClass();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        this.a.C(i, i2, intent);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.a.A(bundle);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onDestroy() {
        super.onDestroy();
        C0122z c0122z = this.a;
        c0122z.b = 5;
        Iterator it2 = ((Map) c0122z.c).values().iterator();
        while (it2.hasNext()) {
            ((l) it2.next()).getClass();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() {
        super.onResume();
        C0122z c0122z = this.a;
        c0122z.b = 3;
        Iterator it2 = ((Map) c0122z.c).values().iterator();
        while (it2.hasNext()) {
            ((l) it2.next()).d();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle bundle) {
        this.a.D(bundle);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        C0122z c0122z = this.a;
        c0122z.b = 2;
        for (l lVar : ((Map) c0122z.c).values()) {
            lVar.b = true;
            lVar.d();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onStop() {
        super.onStop();
        C0122z c0122z = this.a;
        c0122z.b = 4;
        Iterator it2 = ((Map) c0122z.c).values().iterator();
        while (it2.hasNext()) {
            ((l) it2.next()).c();
        }
    }

    @Override // com.google.android.gms.common.api.internal.InterfaceC1649g
    public final void v(l lVar) {
        this.a.z(lVar);
    }
}
