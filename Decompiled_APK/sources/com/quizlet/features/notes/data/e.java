package com.quizlet.features.notes.data;

import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final String a;

    public e(String description) {
        Intrinsics.checkNotNullParameter(description, "description");
        this.a = description;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        eVar.getClass();
        return Intrinsics.b(this.a, eVar.a);
    }

    public final int hashCode() {
        return this.a.hashCode() + (Integer.hashCode(R.string.magic_notes_detail_original_upload_title) * 31);
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("ModalInfo(title=2132018785, description="), this.a, ")");
    }
}
