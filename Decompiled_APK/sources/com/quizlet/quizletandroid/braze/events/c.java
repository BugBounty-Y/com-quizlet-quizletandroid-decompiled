package com.quizlet.quizletandroid.braze.events;

import androidx.compose.animation.core.J0;
import androidx.compose.animation.d0;
import com.braze.models.outgoing.BrazeProperties;
import com.quizlet.generated.enums.EnumC4509p;
import com.quizlet.generated.enums.EnumC4520t;
import com.quizlet.generated.enums.r;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;

/* loaded from: classes3.dex */
public final class c extends J0 {
    public final long c;
    public final EnumC4509p d;
    public final String e;
    public final r f;
    public final EnumC4520t g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(long j, EnumC4509p studiableType, String studiableName, r studyMode, EnumC4520t enumC4520t) throws JSONException {
        String strA;
        super(9);
        Intrinsics.checkNotNullParameter(studiableType, "studiableType");
        Intrinsics.checkNotNullParameter(studiableName, "studiableName");
        Intrinsics.checkNotNullParameter(studyMode, "studyMode");
        this.c = j;
        this.d = studiableType;
        this.e = studiableName;
        this.f = studyMode;
        this.g = enumC4520t;
        BrazeProperties brazeProperties = new BrazeProperties();
        brazeProperties.addProperty("studiable_id", Long.valueOf(j));
        brazeProperties.addProperty("studiable_type", studiableType.a());
        brazeProperties.addProperty("studiable_name", studiableName);
        brazeProperties.addProperty("study_mode", studyMode.a());
        if (enumC4520t != null && (strA = enumC4520t.a()) != null) {
            brazeProperties.addProperty("study_step", strA);
        }
        this.b = brazeProperties;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.c == cVar.c && this.d == cVar.d && Intrinsics.b(this.e, cVar.e) && this.f == cVar.f && this.g == cVar.g;
    }

    public final int hashCode() {
        int iHashCode = (this.f.hashCode() + d0.e((this.d.hashCode() + (Long.hashCode(this.c) * 31)) * 31, 31, this.e)) * 31;
        EnumC4520t enumC4520t = this.g;
        return (iHashCode + (enumC4520t == null ? 0 : enumC4520t.hashCode())) * 31;
    }

    @Override // androidx.compose.animation.core.J0
    public final String toString() {
        return "StudySessionBrazeEvent(studiableId=" + this.c + ", studiableType=" + this.d + ", studiableName=" + this.e + ", studyMode=" + this.f + ", studyStep=" + this.g + ", matchScore=null)";
    }

    @Override // androidx.compose.animation.core.J0
    public final String z() {
        return "study_session";
    }
}
