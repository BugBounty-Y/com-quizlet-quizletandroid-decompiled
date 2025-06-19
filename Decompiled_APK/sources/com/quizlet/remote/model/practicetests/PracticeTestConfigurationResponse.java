package com.quizlet.remote.model.practicetests;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestConfigurationResponse {
    public final int a;
    public final List b;
    public final Long c;
    public final String d;
    public final boolean e;
    public final boolean f;
    public final List g;
    public final List h;

    public PracticeTestConfigurationResponse(int i, List questionFormats, Long l, String testView, boolean z, boolean z2, List mediaTypes, List contentFormats) {
        Intrinsics.checkNotNullParameter(questionFormats, "questionFormats");
        Intrinsics.checkNotNullParameter(testView, "testView");
        Intrinsics.checkNotNullParameter(mediaTypes, "mediaTypes");
        Intrinsics.checkNotNullParameter(contentFormats, "contentFormats");
        this.a = i;
        this.b = questionFormats;
        this.c = l;
        this.d = testView;
        this.e = z;
        this.f = z2;
        this.g = mediaTypes;
        this.h = contentFormats;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestConfigurationResponse)) {
            return false;
        }
        PracticeTestConfigurationResponse practiceTestConfigurationResponse = (PracticeTestConfigurationResponse) obj;
        return this.a == practiceTestConfigurationResponse.a && Intrinsics.b(this.b, practiceTestConfigurationResponse.b) && Intrinsics.b(this.c, practiceTestConfigurationResponse.c) && Intrinsics.b(this.d, practiceTestConfigurationResponse.d) && this.e == practiceTestConfigurationResponse.e && this.f == practiceTestConfigurationResponse.f && Intrinsics.b(this.g, practiceTestConfigurationResponse.g) && Intrinsics.b(this.h, practiceTestConfigurationResponse.h);
    }

    public final int hashCode() {
        int iF = d0.f(Integer.hashCode(this.a) * 31, 31, this.b);
        Long l = this.c;
        return this.h.hashCode() + d0.f(d0.g(d0.g(d0.e((iF + (l == null ? 0 : l.hashCode())) * 31, 31, this.d), 31, this.e), 31, this.f), 31, this.g);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestConfigurationResponse(questionCount=");
        sb.append(this.a);
        sb.append(", questionFormats=");
        sb.append(this.b);
        sb.append(", testTimer=");
        sb.append(this.c);
        sb.append(", testView=");
        sb.append(this.d);
        sb.append(", enableTestTimer=");
        sb.append(this.e);
        sb.append(", enableTimerSound=");
        sb.append(this.f);
        sb.append(", mediaTypes=");
        sb.append(this.g);
        sb.append(", contentFormats=");
        return android.support.v4.media.session.a.n(")", sb, this.h);
    }

    public PracticeTestConfigurationResponse(int i, List list, Long l, String str, boolean z, boolean z2, List list2, List list3, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(i, list, l, str, z, z2, (i2 & 64) != 0 ? K.a : list2, (i2 & 128) != 0 ? K.a : list3);
    }
}
