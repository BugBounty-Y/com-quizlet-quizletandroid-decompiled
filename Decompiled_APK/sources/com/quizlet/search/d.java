package com.quizlet.search;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.compose.animation.d0;
import androidx.fragment.app.I;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3721s5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.M5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.i7;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.explanations.questiondetail.data.QuestionDetailSetUpState;
import com.quizlet.explanations.questiondetail.ui.QuestionDetailActivity;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import com.quizlet.explanations.textbook.ui.TextbookActivity;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.quizletandroid.ui.group.GroupActivity;
import com.quizlet.quizletandroid.ui.live.QuizletLiveActivity;
import com.quizlet.quizletandroid.ui.live.interstitial.QuizletLiveInterstitialActivity;
import com.quizlet.quizletandroid.ui.preview.SetPreviewActivity;
import com.quizlet.quizletandroid.ui.profile.ProfileActivity;
import com.quizlet.quizletandroid.ui.qrcodes.QLiveQrCodeReaderActivity;
import com.quizlet.search.data.term.TermSearchUiModel;
import java.io.Serializable;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.internal.platform.m;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ NewSearchFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(NewSearchFragment newSearchFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = newSearchFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        d dVar = new d(this.k, hVar);
        dVar.j = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((com.quizlet.search.navigation.l) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Intent intentB;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.search.navigation.l lVar = (com.quizlet.search.navigation.l) this.j;
        String str = NewSearchFragment.o;
        NewSearchFragment newSearchFragment = this.k;
        if (lVar instanceof com.quizlet.search.navigation.a) {
            I iRequireActivity = newSearchFragment.requireActivity();
            if (iRequireActivity.getSupportFragmentManager().J() > 0) {
                iRequireActivity.getSupportFragmentManager().V();
            } else {
                iRequireActivity.finish();
            }
        } else {
            if (lVar instanceof com.quizlet.search.navigation.b) {
                newSearchFragment.U();
                Context context = newSearchFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
                long j = ((com.quizlet.search.navigation.b) lVar).a;
                Intrinsics.checkNotNullParameter(context, "context");
                String str2 = GroupActivity.u;
                context.startActivity(com.quizlet.quizletandroid.ui.group.f.a(context, Long.valueOf(j), null, false, null));
            } else if (lVar instanceof com.quizlet.search.navigation.d) {
                newSearchFragment.U();
                Context context2 = newSearchFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context2, "requireContext(...)");
                String id = ((com.quizlet.search.navigation.d) lVar).a;
                Intrinsics.checkNotNullParameter(context2, "context");
                Intrinsics.checkNotNullParameter(id, "id");
                QuestionDetailSetUpState.WithId withId = new QuestionDetailSetUpState.WithId(id);
                String str3 = QuestionDetailActivity.t;
                context2.startActivity(i7.a(context2, withId));
            } else if (lVar instanceof com.quizlet.search.navigation.g) {
                newSearchFragment.U();
                Context context3 = newSearchFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context3, "requireContext(...)");
                long j2 = ((com.quizlet.search.navigation.g) lVar).a;
                Intrinsics.checkNotNullParameter(context3, "context");
                com.quizlet.features.setpage.e eVar = SetPageActivity.h1;
                context3.startActivity(com.quizlet.features.setpage.e.c(28, j2, context3));
            } else if (lVar instanceof com.quizlet.search.navigation.j) {
                newSearchFragment.U();
                Context context4 = newSearchFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context4, "requireContext(...)");
                String isbn = ((com.quizlet.search.navigation.j) lVar).a;
                Intrinsics.checkNotNullParameter(context4, "context");
                Intrinsics.checkNotNullParameter(isbn, "isbn");
                Intrinsics.checkNotNullParameter(isbn, "isbn");
                TextbookSetUpState.TableOfContents tableOfContents = new TextbookSetUpState.TableOfContents(isbn);
                String str4 = TextbookActivity.r;
                context4.startActivity(m.c(context4, tableOfContents));
            } else if (lVar instanceof com.quizlet.search.navigation.k) {
                newSearchFragment.U();
                Context context5 = newSearchFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context5, "requireContext(...)");
                long j3 = ((com.quizlet.search.navigation.k) lVar).a;
                Intrinsics.checkNotNullParameter(context5, "context");
                context5.startActivity(ProfileActivity.p.g(context5, j3));
            } else if (lVar instanceof com.quizlet.search.navigation.h) {
                newSearchFragment.U();
                Context context6 = newSearchFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context6, "requireContext(...)");
                com.quizlet.search.navigation.h hVar = (com.quizlet.search.navigation.h) lVar;
                long j4 = hVar.a;
                Intrinsics.checkNotNullParameter(context6, "context");
                List list = hVar.b;
                Intrinsics.checkNotNullParameter(list, "ids");
                String str5 = SetPreviewActivity.u;
                Intrinsics.checkNotNullParameter(context6, "context");
                Intrinsics.checkNotNullParameter(list, "list");
                Intent intent = new Intent(context6, (Class<?>) SetPreviewActivity.class);
                intent.putExtra("id", j4);
                intent.putExtra("setIds", (Serializable) list);
                context6.startActivity(intent);
            } else if (lVar instanceof com.quizlet.search.navigation.c) {
                newSearchFragment.U();
                Context context7 = newSearchFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context7, "requireContext(...)");
                com.quizlet.ui.models.webpage.k webPage = ((com.quizlet.search.navigation.c) lVar).a;
                Intrinsics.checkNotNullParameter(context7, "context");
                Intrinsics.checkNotNullParameter(webPage, "webPage");
                com.quizlet.quizletandroid.ui.webpages.a.a.c(context7, webPage);
            } else if (lVar instanceof com.quizlet.search.navigation.f) {
                com.quizlet.search.navigation.f fVar = (com.quizlet.search.navigation.f) lVar;
                int iOrdinal = fVar.a.ordinal();
                if (iOrdinal == 0) {
                    com.quizlet.search.navigation.m mVarU = newSearchFragment.U();
                    Context context8 = newSearchFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(context8, "requireContext(...)");
                    androidx.activity.result.b activityResultLauncher = newSearchFragment.k;
                    if (activityResultLauncher == null) {
                        Intrinsics.m("quizletLiveResultLauncher");
                        throw null;
                    }
                    Intrinsics.checkNotNullParameter(context8, "context");
                    Intrinsics.checkNotNullParameter(activityResultLauncher, "activityResultLauncher");
                    com.quizlet.data.interactor.school.b bVar = ((com.quizlet.quizletandroid.ui.navigationmanagers.g) mVarU).a;
                    Intrinsics.checkNotNullParameter(context8, "context");
                    Intrinsics.checkNotNullParameter(activityResultLauncher, "activityResultLauncher");
                    long personId = ((com.quizlet.infra.legacysyncengine.managers.d) bVar.c).e.getPersonId();
                    com.quizlet.infra.legacysyncengine.managers.g gVar = (com.quizlet.infra.legacysyncengine.managers.g) bVar.b;
                    boolean z = gVar.a.getInt(d0.s(new Object[]{Long.valueOf(personId)}, 1, "user_preferred_join_method_%s", "format(...)"), 0) > 0;
                    com.quizlet.infra.legacysyncengine.managers.f userLastJoinMethod = gVar.a(personId);
                    Intrinsics.checkNotNullParameter(context8, "context");
                    Intrinsics.checkNotNullParameter(userLastJoinMethod, "userLastJoinMethod");
                    if (z) {
                        int iOrdinal2 = userLastJoinMethod.ordinal();
                        if (iOrdinal2 == 0) {
                            int i = QuizletLiveActivity.z;
                            intentB = AbstractC3721s5.b(context8);
                        } else {
                            if (iOrdinal2 != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            String str6 = QLiveQrCodeReaderActivity.t;
                            intentB = M5.b(context8);
                        }
                    } else {
                        int i2 = QuizletLiveInterstitialActivity.q;
                        intentB = AbstractC4178x.b(context8, "context", context8, QuizletLiveInterstitialActivity.class);
                    }
                    activityResultLauncher.a(intentB);
                } else if (iOrdinal == 1) {
                    newSearchFragment.U();
                    Context context9 = newSearchFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(context9, "requireContext(...)");
                    androidx.activity.result.b quizletLiveResultLauncher = newSearchFragment.k;
                    if (quizletLiveResultLauncher == null) {
                        Intrinsics.m("quizletLiveResultLauncher");
                        throw null;
                    }
                    Intrinsics.checkNotNullParameter(context9, "context");
                    Intrinsics.checkNotNullParameter(quizletLiveResultLauncher, "quizletLiveResultLauncher");
                    Intrinsics.checkNotNullParameter(context9, "context");
                    Intrinsics.checkNotNullParameter(quizletLiveResultLauncher, "quizletLiveResultLauncher");
                    String str7 = QLiveQrCodeReaderActivity.t;
                    quizletLiveResultLauncher.a(M5.b(context9));
                } else {
                    if (iOrdinal != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    newSearchFragment.U();
                    Context context10 = newSearchFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(context10, "requireContext(...)");
                    androidx.activity.result.b quizletLiveResultLauncher2 = newSearchFragment.k;
                    if (quizletLiveResultLauncher2 == null) {
                        Intrinsics.m("quizletLiveResultLauncher");
                        throw null;
                    }
                    Intrinsics.checkNotNullParameter(context10, "context");
                    Intrinsics.checkNotNullParameter(quizletLiveResultLauncher2, "quizletLiveResultLauncher");
                    String gameCode = fVar.b;
                    if (gameCode == null) {
                        gameCode = "";
                    }
                    Intrinsics.checkNotNullParameter(context10, "context");
                    Intrinsics.checkNotNullParameter(quizletLiveResultLauncher2, "quizletLiveResultLauncher");
                    Intrinsics.checkNotNullParameter(gameCode, "gameCode");
                    int i3 = QuizletLiveActivity.z;
                    quizletLiveResultLauncher2.a(AbstractC3721s5.c(context10, gameCode));
                }
            } else {
                if (!(lVar instanceof com.quizlet.search.navigation.i)) {
                    throw new NoWhenBranchMatchedException();
                }
                String str8 = TermSearchFragment.V;
                TermSearchUiModel termData = ((com.quizlet.search.navigation.i) lVar).a;
                Intrinsics.checkNotNullParameter(termData, "termData");
                TermSearchFragment termSearchFragment = new TermSearchFragment();
                Bundle bundle = new Bundle();
                bundle.putParcelable("term_data", termData);
                termSearchFragment.setArguments(bundle);
                termSearchFragment.O(newSearchFragment.getChildFragmentManager(), TermSearchFragment.V);
            }
        }
        return Unit.a;
    }
}
