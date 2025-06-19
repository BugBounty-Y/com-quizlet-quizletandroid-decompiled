package androidx.navigation.compose;

import androidx.lifecycle.m0;
import androidx.lifecycle.w0;
import java.lang.ref.WeakReference;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.navigation.compose.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1268a extends w0 {
    public final String b;
    public com.google.android.gms.auth.api.signin.internal.h c;

    public C1268a(@NotNull m0 m0Var) {
        String string = (String) m0Var.a("SaveableStateHolder_BackStackEntryKey");
        if (string == null) {
            string = UUID.randomUUID().toString();
            m0Var.c(string, "SaveableStateHolder_BackStackEntryKey");
        }
        this.b = string;
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        com.google.android.gms.auth.api.signin.internal.h hVar = this.c;
        if (hVar == null) {
            Intrinsics.m("saveableStateHolderRef");
            throw null;
        }
        androidx.compose.runtime.saveable.c cVar = (androidx.compose.runtime.saveable.c) ((WeakReference) hVar.b).get();
        if (cVar != null) {
            cVar.f(this.b);
        }
        com.google.android.gms.auth.api.signin.internal.h hVar2 = this.c;
        if (hVar2 != null) {
            ((WeakReference) hVar2.b).clear();
        } else {
            Intrinsics.m("saveableStateHolderRef");
            throw null;
        }
    }
}
