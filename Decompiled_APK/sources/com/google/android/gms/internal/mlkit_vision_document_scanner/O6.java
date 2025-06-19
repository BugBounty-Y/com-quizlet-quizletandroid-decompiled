package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import com.quizlet.data.model.Course;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsFragment;
import java.util.ArrayList;
import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class O6 {
    public static void a(MatchSettingsFragment matchSettingsFragment, int i, int[] statusTextArgsIds, int i2) {
        if ((i2 & 2) != 0) {
            statusTextArgsIds = new int[0];
        }
        boolean z = (i2 & 4) == 0;
        matchSettingsFragment.getClass();
        Intrinsics.checkNotNullParameter(statusTextArgsIds, "statusTextArgsIds");
        if (z) {
            QTextView matchSettingsMatchGroupStatusError = ((com.quizlet.quizletandroid.databinding.O) matchSettingsFragment.J()).h;
            Intrinsics.checkNotNullExpressionValue(matchSettingsMatchGroupStatusError, "matchSettingsMatchGroupStatusError");
            matchSettingsMatchGroupStatusError.setVisibility(0);
            QTextView matchSettingsMatchGroupStatus = ((com.quizlet.quizletandroid.databinding.O) matchSettingsFragment.J()).g;
            Intrinsics.checkNotNullExpressionValue(matchSettingsMatchGroupStatus, "matchSettingsMatchGroupStatus");
            matchSettingsMatchGroupStatus.setVisibility(8);
            return;
        }
        QTextView matchSettingsMatchGroupStatusError2 = ((com.quizlet.quizletandroid.databinding.O) matchSettingsFragment.J()).h;
        Intrinsics.checkNotNullExpressionValue(matchSettingsMatchGroupStatusError2, "matchSettingsMatchGroupStatusError");
        matchSettingsMatchGroupStatusError2.setVisibility(8);
        QTextView matchSettingsMatchGroupStatus2 = ((com.quizlet.quizletandroid.databinding.O) matchSettingsFragment.J()).g;
        Intrinsics.checkNotNullExpressionValue(matchSettingsMatchGroupStatus2, "matchSettingsMatchGroupStatus");
        matchSettingsMatchGroupStatus2.setVisibility(0);
        QTextView matchSettingsMatchGroupStatus3 = ((com.quizlet.quizletandroid.databinding.O) matchSettingsFragment.J()).g;
        Intrinsics.checkNotNullExpressionValue(matchSettingsMatchGroupStatus3, "matchSettingsMatchGroupStatus");
        Context contextRequireContext = matchSettingsFragment.requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        int[] argsResIds = Arrays.copyOf(statusTextArgsIds, statusTextArgsIds.length);
        Intrinsics.checkNotNullParameter(contextRequireContext, "<this>");
        Intrinsics.checkNotNullParameter(argsResIds, "argsResIds");
        ArrayList arrayList = new ArrayList(argsResIds.length);
        for (int i3 : argsResIds) {
            arrayList.add(contextRequireContext.getString(i3));
        }
        String[] strArr = (String[]) arrayList.toArray(new String[0]);
        String string = contextRequireContext.getString(i, Arrays.copyOf(strArr, strArr.length));
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        matchSettingsMatchGroupStatus3.setText(string);
    }

    public static final com.quizlet.edgy.ui.recyclerview.adapter.g b(Course course) {
        Intrinsics.checkNotNullParameter(course, "<this>");
        long j = course.a;
        String str = course.b;
        String str2 = str == null ? "" : str;
        String str3 = course.c;
        return new com.quizlet.edgy.ui.recyclerview.adapter.g(course.d, j, course.f, course.e, str2, str3 == null ? "" : str3);
    }
}
