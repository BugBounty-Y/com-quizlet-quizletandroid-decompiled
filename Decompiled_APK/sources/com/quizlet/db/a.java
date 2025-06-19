package com.quizlet.db;

import android.content.SharedPreferences;
import androidx.compose.animation.d0;
import com.quizlet.db.data.models.base.SortOption;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final SharedPreferences a;

    public a(SharedPreferences sharedPreferences, int i) {
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
                Intrinsics.checkNotNullParameter("check_in_switch_prompt_tooltip", "key");
                this.a = sharedPreferences;
                break;
            default:
                this.a = sharedPreferences;
                break;
        }
    }

    public SortOption a(long j) {
        return SortOption.fromInt(this.a.getInt(d0.o(j, "set_page_", "_sort_option"), SortOption.ORIGINAL.getValue()));
    }
}
