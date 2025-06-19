package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import com.quizlet.data.model.B0;
import com.quizlet.generated.enums.EnumC4525u1;
import com.quizlet.generated.enums.w1;
import com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class F extends AbstractC4707c implements InterfaceC4751w {
    public final B0 d;
    public final boolean e;
    public final String f;
    public final int g;
    public final w1 h;
    public final EnumC4525u1 i;
    public final String j;

    public F(B0 data, boolean z, String str, int i, w1 subplacement) {
        EnumC4525u1 placement = EnumC4525u1.HOMESCREEN;
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(subplacement, "subplacement");
        Intrinsics.checkNotNullParameter(placement, "placement");
        this.d = data;
        this.e = z;
        this.f = str;
        this.g = i;
        this.h = subplacement;
        this.i = placement;
        this.j = AbstractC0147y.d("explanations_home_data_", data.getItemId());
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final w1 a() {
        return this.h;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final Long b() {
        return null;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final EnumC4525u1 c() {
        return this.i;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.model.AbstractC4707c
    public final String d() {
        return this.f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof F)) {
            return false;
        }
        F f = (F) obj;
        return Intrinsics.b(this.d, f.d) && this.e == f.e && Intrinsics.b(this.f, f.f) && this.g == f.g && this.h == f.h && this.i == f.i;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return this.j;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final int getModelType() {
        return this.g;
    }

    public final int hashCode() {
        int iG = d0.g(this.d.hashCode() * 31, 31, this.e);
        String str = this.f;
        return this.i.hashCode() + ((this.h.hashCode() + d0.b(this.g, (iG + (str == null ? 0 : str.hashCode())) * 31, 31)) * 31);
    }

    public final String toString() {
        return "MyExplanationsHomeData(data=" + this.d + ", isPlusUser=" + this.e + ", modelIdString=" + this.f + ", modelType=" + this.g + ", subplacement=" + this.h + ", placement=" + this.i + ")";
    }
}
