package com.quizlet.assembly.compose.listitems;

import androidx.compose.runtime.C0776c;
import com.comscore.streaming.EventType;
import com.quizlet.data.connectivity.NetworkOfflineError;
import com.quizlet.data.model.C4160q1;
import com.quizlet.db.data.models.persisted.types.AnswerModel;
import com.quizlet.db.data.models.persisted.types.BookmarkModel;
import com.quizlet.db.data.models.persisted.types.DiagramShapeModel;
import com.quizlet.db.data.models.persisted.types.EnteredSetPasswordModel;
import com.quizlet.db.data.models.persisted.types.FolderModel;
import com.quizlet.db.data.models.persisted.types.GroupFolderModel;
import com.quizlet.db.data.models.persisted.types.GroupMembershipModel;
import com.quizlet.db.data.models.persisted.types.GroupModel;
import com.quizlet.db.data.models.persisted.types.GroupSetModel;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class r implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ r(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Unit.a;
            case 1:
                return Unit.a;
            case 2:
                return Unit.a;
            case 3:
                return Unit.a;
            case 4:
                return Unit.a;
            case 5:
                return Unit.a;
            case 6:
                return Unit.a;
            case 7:
                return Unit.a;
            case 8:
                return Unit.a;
            case 9:
                return Unit.a;
            case 10:
                return Unit.a;
            case 11:
                return Unit.a;
            case 12:
                return C0776c.z("");
            case 13:
                return Unit.a;
            case 14:
                return Unit.a;
            case 15:
                return Unit.a;
            case 16:
                return Unit.a;
            case 17:
                return io.reactivex.rxjava3.core.p.d(new NetworkOfflineError(0));
            case 18:
                io.reactivex.rxjava3.internal.operators.flowable.b bVarF = io.reactivex.rxjava3.core.p.f(-1);
                Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
                return bVarF;
            case 19:
                io.reactivex.rxjava3.internal.operators.flowable.b bVarF2 = io.reactivex.rxjava3.core.p.f(new C4160q1(K.a, null, null));
                Intrinsics.checkNotNullExpressionValue(bVarF2, "just(...)");
                return bVarF2;
            case 20:
                io.reactivex.rxjava3.internal.operators.flowable.b bVarF3 = io.reactivex.rxjava3.core.p.f(K.a);
                Intrinsics.checkNotNullExpressionValue(bVarF3, "just(...)");
                return bVarF3;
            case 21:
                return AnswerModel.mIdentityFields_delegate$lambda$0();
            case EventType.WINDOW_STATE /* 22 */:
                return BookmarkModel.mIdentityFields_delegate$lambda$0();
            case EventType.AUDIO /* 23 */:
                return DiagramShapeModel.mIdentityFields_delegate$lambda$0();
            case EventType.VIDEO /* 24 */:
                return EnteredSetPasswordModel.mIdentityFields_delegate$lambda$0();
            case EventType.SUBS /* 25 */:
                return FolderModel.mIdentityFields_delegate$lambda$0();
            case EventType.CDN /* 26 */:
                return GroupFolderModel.mIdentityFields_delegate$lambda$0();
            case 27:
                return GroupMembershipModel.mIdentityFields_delegate$lambda$0();
            case 28:
                return GroupModel.mIdentityFields_delegate$lambda$0();
            default:
                return GroupSetModel.mIdentityFields_delegate$lambda$0();
        }
    }
}
