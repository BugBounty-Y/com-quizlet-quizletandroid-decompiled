package com.quizlet.quizletandroid.ui.startpage.nav2.adapters;

import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.F0;
import com.onetrust.otpublishers.headless.UI.adapter.s;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.S;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r extends a {
    public final Y c;
    public final Y d;
    public final com.quizlet.infra.legacysyncengine.managers.d e;
    public final int f;

    public r(Y setNavDelegate, Y studiableLoggingDelegate, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, int i) {
        Intrinsics.checkNotNullParameter(setNavDelegate, "setNavDelegate");
        Intrinsics.checkNotNullParameter(studiableLoggingDelegate, "studiableLoggingDelegate");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        s diffUtilCallback = new s(2);
        Intrinsics.checkNotNullParameter(diffUtilCallback, "diffUtilCallback");
        super(diffUtilCallback);
        this.c = setNavDelegate;
        this.d = studiableLoggingDelegate;
        this.e = loggedInUserManager;
        this.f = i;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        int i2 = y.d;
        return R.layout.nav2_listitem_new_study_set;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        y holder = (y) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        S s = (S) d(i);
        DBStudySet studySet = s.d;
        com.quizlet.features.questionnaire.screens.c onClick = new com.quizlet.features.questionnaire.screens.c(29, this, s);
        Integer numValueOf = Integer.valueOf(this.f);
        DBUser dBUser = this.e.r;
        holder.getClass();
        Intrinsics.checkNotNullParameter(studySet, "studySet");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        ((com.quizlet.quizletandroid.databinding.Y) holder.e()).b.setContent(new androidx.compose.runtime.internal.d(true, 795968281, new com.quizlet.features.infra.folder.create.composables.a(dBUser, studySet, onClick, s.i, this.c, numValueOf)));
        Boolean tag = Boolean.valueOf(s.a);
        Intrinsics.checkNotNullParameter(tag, "tag");
        holder.itemView.setTag(R.id.unifiedRecyclerView, tag);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View itemView = com.quizlet.baserecyclerview.b.g(parent, i);
        a.h(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        return new y(itemView);
    }
}
