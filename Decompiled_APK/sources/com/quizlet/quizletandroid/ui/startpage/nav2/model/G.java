package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.EnumC4525u1;
import com.quizlet.generated.enums.w1;
import com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class G extends AbstractC4707c implements InterfaceC4751w {
    public final com.quizlet.ui.models.content.carditem.d d;
    public final int e;
    public final w1 f;
    public final EnumC4525u1 g;
    public final String h;
    public final String i;

    public G(com.quizlet.ui.models.content.carditem.d data, w1 subplacement) {
        EnumC4525u1 placement = EnumC4525u1.HOMESCREEN;
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(subplacement, "subplacement");
        Intrinsics.checkNotNullParameter(placement, "placement");
        this.d = data;
        this.e = 20;
        this.f = subplacement;
        this.g = placement;
        StringBuilder sb = new StringBuilder("note_id_");
        String str = data.a;
        sb.append(str);
        this.h = sb.toString();
        this.i = str;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final w1 a() {
        return this.f;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final Long b() {
        return null;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final EnumC4525u1 c() {
        return this.g;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.model.AbstractC4707c
    public final String e() {
        return this.i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof G)) {
            return false;
        }
        G g = (G) obj;
        return Intrinsics.b(this.d, g.d) && this.e == g.e && this.f == g.f && this.g == g.g;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return this.h;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final int getModelType() {
        return this.e;
    }

    public final int hashCode() {
        return this.g.hashCode() + ((this.f.hashCode() + d0.b(this.e, this.d.hashCode() * 31, 31)) * 31);
    }

    public final String toString() {
        return "NoteHomeData(data=" + this.d + ", modelType=" + this.e + ", subplacement=" + this.f + ", placement=" + this.g + ")";
    }
}
