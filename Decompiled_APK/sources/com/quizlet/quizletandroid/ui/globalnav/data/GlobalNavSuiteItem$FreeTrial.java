package com.quizlet.quizletandroid.ui.globalnav.data;

import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class GlobalNavSuiteItem$FreeTrial extends k {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String c;
    public final String d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return GlobalNavSuiteItem$FreeTrial$$serializer.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ GlobalNavSuiteItem$FreeTrial(String str, int i, String str2, int i2) {
        super(i2);
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, GlobalNavSuiteItem$FreeTrial$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.c = str;
        this.d = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GlobalNavSuiteItem$FreeTrial)) {
            return false;
        }
        GlobalNavSuiteItem$FreeTrial globalNavSuiteItem$FreeTrial = (GlobalNavSuiteItem$FreeTrial) obj;
        return Intrinsics.b(this.c, globalNavSuiteItem$FreeTrial.c) && Intrinsics.b(this.d, globalNavSuiteItem$FreeTrial.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + (this.c.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FreeTrial(upgradeSource=");
        sb.append(this.c);
        sb.append(", navigationSource=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public GlobalNavSuiteItem$FreeTrial(String upgradeSource, String navigationSource) {
        super(R.string.global_nav_item_label_free_trial, 0);
        Intrinsics.checkNotNullParameter(upgradeSource, "upgradeSource");
        Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
        this.c = upgradeSource;
        this.d = navigationSource;
    }
}
