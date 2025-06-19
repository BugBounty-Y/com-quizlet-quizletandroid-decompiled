package com.quizlet.ui.models.content.ads;

import androidx.compose.ui.node.B;
import com.google.android.gms.ads.k;
import com.quizlet.generated.enums.K0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.ui.models.search.a, com.quizlet.ui.models.impressions.a {
    public final k a;
    public final String b = B.f("toString(...)");
    public final int c = -1;
    public final K0 d = K0.FREE;

    public a(k kVar) {
        this.a = kVar;
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final K0 a() {
        return this.d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final long getItemId() {
        return -1L;
    }

    @Override // com.quizlet.ui.models.search.a
    public final Object getKey() {
        return this.b;
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final int getModelType() {
        return this.c;
    }

    public final int hashCode() {
        k kVar = this.a;
        if (kVar == null) {
            return 0;
        }
        return kVar.hashCode();
    }

    public final String toString() {
        return "AdUiModel(baseAdView=" + this.a + ")";
    }
}
