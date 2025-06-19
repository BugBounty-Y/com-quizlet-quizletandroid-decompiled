package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.EnumC4525u1;
import com.quizlet.generated.enums.w1;
import com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.model.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4717m extends AbstractC4707c implements InterfaceC4751w {
    public final com.quizlet.ui.models.content.carditem.c d;
    public final Long e;
    public final int f;
    public final w1 g;
    public final EnumC4525u1 h;
    public final String i;

    public C4717m(com.quizlet.ui.models.content.carditem.c data, Long l, w1 subplacement) {
        EnumC4525u1 placement = EnumC4525u1.HOMESCREEN;
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(subplacement, "subplacement");
        Intrinsics.checkNotNullParameter(placement, "placement");
        this.d = data;
        this.e = l;
        this.f = 3;
        this.g = subplacement;
        this.h = placement;
        this.i = "folder_id_" + l;
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
        if (!(obj instanceof C4717m)) {
            return false;
        }
        C4717m c4717m = (C4717m) obj;
        return Intrinsics.b(this.d, c4717m.d) && Intrinsics.b(this.e, c4717m.e) && this.f == c4717m.f && this.g == c4717m.g && this.h == c4717m.h;
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
        return "FolderHomeData(data=" + this.d + ", modelId=" + this.e + ", modelType=" + this.f + ", subplacement=" + this.g + ", placement=" + this.h + ")";
    }
}
