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
public final class GlobalNavSuiteItem$YourLibrary extends k {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return GlobalNavSuiteItem$YourLibrary$$serializer.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ GlobalNavSuiteItem$YourLibrary(int i, int i2, String str) {
        super(i2);
        if (1 != (i & 1)) {
            AbstractC5047c0.k(i, 1, GlobalNavSuiteItem$YourLibrary$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        if ((i & 2) == 0) {
            this.c = null;
        } else {
            this.c = str;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof GlobalNavSuiteItem$YourLibrary) && Intrinsics.b(this.c, ((GlobalNavSuiteItem$YourLibrary) obj).c);
    }

    public final int hashCode() {
        String str = this.c;
        if (str == null) {
            return 0;
        }
        return str.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("YourLibrary(tab="), this.c, ")");
    }

    public GlobalNavSuiteItem$YourLibrary(String str) {
        super(R.string.bottom_nav_item_title_library, 0);
        this.c = str;
    }
}
