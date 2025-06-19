package com.quizlet.ui.models.content.carditem;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.K0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class e implements com.quizlet.ui.models.search.a, com.quizlet.ui.models.impressions.a {
    public final String a;
    public final String b;
    public final String c;
    public final Integer d;
    public final boolean e;
    public final K0 f;

    public e(String id, String prompt, String slug, Integer num, boolean z) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(slug, "slug");
        this.a = id;
        this.b = prompt;
        this.c = slug;
        this.d = num;
        this.e = z;
        this.f = K0.FREE;
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final K0 a() {
        return this.f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b) && Intrinsics.b(this.c, eVar.c) && Intrinsics.b(this.d, eVar.d) && this.e == eVar.e;
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final long getItemId() {
        Long lF0 = StringsKt.f0(this.a);
        if (lF0 != null) {
            return lF0.longValue();
        }
        return 0L;
    }

    @Override // com.quizlet.ui.models.search.a
    public final Object getKey() {
        return this.a;
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final int getModelType() {
        return 16;
    }

    public final int hashCode() {
        int iE = d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c);
        Integer num = this.d;
        return Boolean.hashCode(this.e) + ((iE + (num == null ? 0 : num.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuestionCardUiModel(id=");
        sb.append(this.a);
        sb.append(", prompt=");
        sb.append(this.b);
        sb.append(", slug=");
        sb.append(this.c);
        sb.append(", subject=");
        sb.append(this.d);
        sb.append(", isPlus=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
