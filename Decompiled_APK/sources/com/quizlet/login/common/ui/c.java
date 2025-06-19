package com.quizlet.login.common.ui;

import androidx.compose.material3.InterfaceC0764y3;
import com.quizlet.login.common.interactors.data.C4590a;

/* loaded from: classes3.dex */
public final class c implements InterfaceC0764y3 {
    public final /* synthetic */ C4590a a;

    public c(C4590a c4590a) {
        this.a = c4590a;
    }

    @Override // androidx.compose.material3.InterfaceC0764y3
    public final boolean a(long j) {
        return j <= this.a.a;
    }

    @Override // androidx.compose.material3.InterfaceC0764y3
    public final boolean b(int i) {
        return i <= this.a.b;
    }
}
