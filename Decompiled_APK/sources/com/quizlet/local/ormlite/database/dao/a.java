package com.quizlet.local.ormlite.database.dao;

import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.persisted.base.Models;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ DatabaseHelper b;

    public /* synthetic */ a(DatabaseHelper databaseHelper, int i) {
        this.a = i;
        this.b = databaseHelper;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.i(Models.BOOKMARK);
            case 1:
                return this.b.i(Models.FOLDER);
            case 2:
                return this.b.i(Models.GROUP_FOLDER);
            case 3:
                return this.b.i(Models.GROUP_MEMBERSHIP);
            case 4:
                return this.b.i(Models.GROUP_SET);
            case 5:
                return this.b.i(Models.PROGRESS_RESET);
            case 6:
                return this.b.i(Models.SELECTED_TERM);
            case 7:
                return this.b.i(Models.STUDY_SET);
            case 8:
                return this.b.i(Models.TERM);
            default:
                return this.b.i(Models.USER);
        }
    }
}
