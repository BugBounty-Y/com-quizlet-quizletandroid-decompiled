package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.EnumC4525u1;
import com.quizlet.generated.enums.w1;
import com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.model.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4718n extends AbstractC4707c implements InterfaceC4751w {
    public final com.quizlet.ui.models.content.carditem.a d;
    public final Long e;
    public final int f;
    public final w1 g;
    public final EnumC4525u1 h;
    public final String i;

    public C4718n(com.quizlet.ui.models.content.carditem.a data, Long l, w1 subplacement) {
        EnumC4525u1 placement = EnumC4525u1.HOMESCREEN;
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(subplacement, "subplacement");
        Intrinsics.checkNotNullParameter(placement, "placement");
        this.d = data;
        this.e = l;
        this.f = 4;
        this.g = subplacement;
        this.h = placement;
        this.i = "group_id_" + l;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final w1 a() {
        return this.g;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final Long b() {
        return this.e;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final EnumC4525u1 c() {
        return this.h;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4718n)) {
            return false;
        }
        C4718n c4718n = (C4718n) obj;
        return Intrinsics.b(this.d, c4718n.d) && Intrinsics.b(this.e, c4718n.e) && this.f == c4718n.f && this.g == c4718n.g && this.h == c4718n.h;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return this.i;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final int getModelType() {
        return this.f;
    }

    public final int hashCode() {
        int iHashCode = this.d.hashCode() * 31;
        Long l = this.e;
        return this.h.hashCode() + ((this.g.hashCode() + d0.b(this.f, (iHashCode + (l == null ? 0 : l.hashCode())) * 31, 31)) * 31);
    }

    public final String toString() {
        return "GroupHomeData(data=" + this.d + ", modelId=" + this.e + ", modelType=" + this.f + ", subplacement=" + this.g + ", placement=" + this.h + ")";
    }
}
