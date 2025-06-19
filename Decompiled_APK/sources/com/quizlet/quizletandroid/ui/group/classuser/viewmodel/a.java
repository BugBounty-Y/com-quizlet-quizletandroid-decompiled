package com.quizlet.quizletandroid.ui.group.classuser.viewmodel;

import androidx.lifecycle.m0;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import com.quizlet.infra.legacysyncengine.net.c;
import com.quizlet.infra.legacysyncengine.orm.b;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class a extends com.quizlet.quizletandroid.ui.base.viewmodel.a {
    public final long g;

    public a(m0 savedStateHandle, com.quizlet.data.interactor.course.a groupDataSourceFactory) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(groupDataSourceFactory, "groupDataSourceFactory");
        Object objA = savedStateHandle.a("KEY_GROUP_CLASS_ID");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        Long lValueOf = Long.valueOf(((Number) objA).longValue());
        b bVar = new b(Models.GROUP_MEMBERSHIP);
        bVar.b(lValueOf, DBGroupMembershipFields.CLASS);
        bVar.e(DBGroupMembershipFields.USER);
        super(new com.quizlet.features.infra.studysetting.datasource.a((c) groupDataSourceFactory.b, bVar.a()));
        Object objA2 = savedStateHandle.a("KEY_GROUP_CLASS_ID");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.g = ((Number) objA2).longValue();
    }
}
