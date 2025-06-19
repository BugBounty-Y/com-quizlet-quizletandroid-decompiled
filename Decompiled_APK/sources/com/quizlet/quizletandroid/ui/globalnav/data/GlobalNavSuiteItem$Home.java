package com.quizlet.quizletandroid.ui.globalnav.data;

import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class GlobalNavSuiteItem$Home extends k {

    @NotNull
    public static final GlobalNavSuiteItem$Home INSTANCE = new GlobalNavSuiteItem$Home(R.string.global_nav_item_label_home, 0);
    public static final /* synthetic */ Object c = kotlin.l.a(kotlin.m.b, new com.quizlet.login.resetpassword.ui.a(12));

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof GlobalNavSuiteItem$Home);
    }

    public final int hashCode() {
        return 645010614;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, kotlin.k] */
    @NotNull
    public final KSerializer serializer() {
        return (KSerializer) c.getValue();
    }

    public final String toString() {
        return "Home";
    }
}
