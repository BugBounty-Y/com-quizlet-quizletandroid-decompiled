package com.quizlet.explanations.questiondetail.recyclerview;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.c7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.h7;
import com.quizlet.data.model.SimpleImage;
import com.quizlet.data.model.X;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e extends g {
    public final String b;
    public final h7 c;
    public final SimpleImage d;
    public final boolean e;
    public final boolean f;
    public final X g;
    public final Function0 h;
    public final Function1 i;

    public e(String str, h7 toggleState, SimpleImage simpleImage, boolean z, boolean z2, X x, Function0 onToggleClick, Function1 onImageLongClick) {
        Intrinsics.checkNotNullParameter(toggleState, "toggleState");
        Intrinsics.checkNotNullParameter(onToggleClick, "onToggleClick");
        Intrinsics.checkNotNullParameter(onImageLongClick, "onImageLongClick");
        this.b = str;
        this.c = toggleState;
        this.d = simpleImage;
        this.e = z;
        this.f = z2;
        this.g = x;
        this.h = onToggleClick;
        this.i = onImageLongClick;
        if (!((Boolean) this.a.getValue()).booleanValue() || x == null) {
            return;
        }
        c7.c(x);
    }

    @Override // com.quizlet.explanations.questiondetail.recyclerview.g
    public final Function1 a() {
        return this.i;
    }

    @Override // com.quizlet.explanations.questiondetail.recyclerview.g
    public final SimpleImage b() {
        return this.d;
    }

    @Override // com.quizlet.explanations.questiondetail.recyclerview.g
    public final String c() {
        return this.b;
    }

    @Override // com.quizlet.explanations.questiondetail.recyclerview.g
    public final boolean d() {
        return this.f;
    }

    @Override // com.quizlet.explanations.questiondetail.recyclerview.g
    public final boolean e() {
        return this.e;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.b, eVar.b) && Intrinsics.b(this.c, eVar.c) && Intrinsics.b(this.d, eVar.d) && this.e == eVar.e && this.f == eVar.f && Intrinsics.b(this.g, eVar.g) && Intrinsics.b(this.h, eVar.h) && Intrinsics.b(this.i, eVar.i);
    }

    public final int hashCode() {
        String str = this.b;
        int iHashCode = (this.c.hashCode() + ((str == null ? 0 : str.hashCode()) * 31)) * 31;
        SimpleImage simpleImage = this.d;
        int iG = d0.g(d0.g((iHashCode + (simpleImage == null ? 0 : simpleImage.hashCode())) * 31, 31, this.e), 31, this.f);
        X x = this.g;
        return this.i.hashCode() + ((this.h.hashCode() + ((iG + (x != null ? x.hashCode() : 0)) * 31)) * 31);
    }

    public final String toString() {
        return "LoggedIn(promptText=" + this.b + ", toggleState=" + this.c + ", promptImage=" + this.d + ", isPlusEnabled=" + this.e + ", isContentLimited=" + this.f + ", meteringInfo=" + this.g + ", onToggleClick=" + this.h + ", onImageLongClick=" + this.i + ")";
    }
}
