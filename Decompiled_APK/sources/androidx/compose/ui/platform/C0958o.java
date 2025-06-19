package androidx.compose.ui.platform;

import android.content.res.Resources;
import com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger;
import com.quizlet.generated.enums.EnumC4484g1;
import com.quizlet.generated.enums.EnumC4490i1;
import com.quizlet.search.data.SearchFilterContentTypeState;
import com.quizlet.search.data.SearchFilterCreatorTypeState;
import com.quizlet.search.data.SearchFilterNumTermsState;
import com.quizlet.search.data.SearchFiltersStates;
import com.quizlet.search.viewmodels.C4800f;
import com.quizlet.search.viewmodels.C4801g;
import com.quizlet.search.viewmodels.C4802h;
import com.quizlet.search.viewmodels.C4803i;
import com.quizlet.studiablemodels.StudiableMeteringData;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.platform.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C0958o extends C4956o implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0958o(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        Object value;
        SearchFilterNumTermsState numTermsFilters;
        SearchFilterCreatorTypeState creatorTypeFilter;
        SearchFilterContentTypeState contentTypeFilters;
        switch (this.a) {
            case 0:
                if (obj != null) {
                    throw new ClassCastException();
                }
                C0971v c0971v = (C0971v) this.receiver;
                Resources resources = c0971v.getContext().getResources();
                return Boolean.valueOf(I.a.a(c0971v, null, new androidx.compose.ui.draganddrop.a(new androidx.compose.ui.unit.c(resources.getDisplayMetrics().density, resources.getConfiguration().fontScale), ((androidx.compose.ui.geometry.e) obj2).a, (Function1) obj3)));
            case 1:
                String className = (String) obj;
                String description = (String) obj2;
                boolean zBooleanValue = ((Boolean) obj3).booleanValue();
                Intrinsics.checkNotNullParameter(className, "p0");
                Intrinsics.checkNotNullParameter(description, "p1");
                com.quizlet.quizletandroid.ui.classcreation.i iVar = (com.quizlet.quizletandroid.ui.classcreation.i) this.receiver;
                iVar.getClass();
                Intrinsics.checkNotNullParameter(className, "className");
                Intrinsics.checkNotNullParameter(description, "description");
                kotlinx.coroutines.E.A(androidx.lifecycle.p0.j(iVar), iVar.g, null, new com.quizlet.quizletandroid.ui.classcreation.h(iVar, className, description, zBooleanValue, null), 2);
                return Unit.a;
            case 2:
                long jLongValue = ((Number) obj).longValue();
                String studySessionId = (String) obj2;
                StudiableMeteringData meteringData = (StudiableMeteringData) obj3;
                Intrinsics.checkNotNullParameter(studySessionId, "p1");
                Intrinsics.checkNotNullParameter(meteringData, "p2");
                StudyModeMeteringEventLogger studyModeMeteringEventLogger = (StudyModeMeteringEventLogger) this.receiver;
                studyModeMeteringEventLogger.getClass();
                Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
                Intrinsics.checkNotNullParameter(meteringData, "meteringData");
                int iOrdinal = meteringData.a.ordinal();
                studyModeMeteringEventLogger.b(jLongValue, meteringData, studySessionId, iOrdinal != 1 ? iOrdinal != 2 ? null : "test_remaining_attempts_paywall_dismiss" : "learn_remaining_rounds_paywall_dismiss");
                return Unit.a;
            case 3:
                long jLongValue2 = ((Number) obj).longValue();
                String studySessionId2 = (String) obj2;
                StudiableMeteringData meteringData2 = (StudiableMeteringData) obj3;
                Intrinsics.checkNotNullParameter(studySessionId2, "p1");
                Intrinsics.checkNotNullParameter(meteringData2, "p2");
                StudyModeMeteringEventLogger studyModeMeteringEventLogger2 = (StudyModeMeteringEventLogger) this.receiver;
                studyModeMeteringEventLogger2.getClass();
                Intrinsics.checkNotNullParameter(studySessionId2, "studySessionId");
                Intrinsics.checkNotNullParameter(meteringData2, "meteringData");
                int iOrdinal2 = meteringData2.a.ordinal();
                studyModeMeteringEventLogger2.b(jLongValue2, meteringData2, studySessionId2, iOrdinal2 != 1 ? iOrdinal2 != 2 ? null : "test_round_complete_paywall_primary_action" : "learn_round_complete_paywall_primary_action");
                return Unit.a;
            case 4:
                long jLongValue3 = ((Number) obj).longValue();
                String studySessionId3 = (String) obj2;
                StudiableMeteringData meteringData3 = (StudiableMeteringData) obj3;
                Intrinsics.checkNotNullParameter(studySessionId3, "p1");
                Intrinsics.checkNotNullParameter(meteringData3, "p2");
                StudyModeMeteringEventLogger studyModeMeteringEventLogger3 = (StudyModeMeteringEventLogger) this.receiver;
                studyModeMeteringEventLogger3.getClass();
                Intrinsics.checkNotNullParameter(studySessionId3, "studySessionId");
                Intrinsics.checkNotNullParameter(meteringData3, "meteringData");
                int iOrdinal3 = meteringData3.a.ordinal();
                studyModeMeteringEventLogger3.b(jLongValue3, meteringData3, studySessionId3, iOrdinal3 != 1 ? iOrdinal3 != 2 ? null : "test_round_complete_paywall_secondary_action" : "learn_round_complete_paywall_secondary_action");
                return Unit.a;
            case 5:
                long jLongValue4 = ((Number) obj).longValue();
                List studySetIds = (List) obj2;
                int iIntValue = ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(studySetIds, "p1");
                com.quizlet.search.viewmodels.p pVar = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar.getClass();
                Intrinsics.checkNotNullParameter(studySetIds, "studySetIds");
                kotlinx.coroutines.E.A(androidx.lifecycle.p0.j(pVar), null, null, new C4802h(pVar, jLongValue4, iIntValue, studySetIds, null), 3);
                return Unit.a;
            case 6:
                long jLongValue5 = ((Number) obj).longValue();
                int iIntValue2 = ((Number) obj2).intValue();
                boolean zBooleanValue2 = ((Boolean) obj3).booleanValue();
                com.quizlet.search.viewmodels.p pVar2 = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar2.getClass();
                kotlinx.coroutines.E.A(androidx.lifecycle.p0.j(pVar2), null, null, new C4801g(pVar2, jLongValue5, iIntValue2, zBooleanValue2, null), 3);
                return Unit.a;
            case 7:
                long jLongValue6 = ((Number) obj).longValue();
                String isbn = (String) obj2;
                int iIntValue3 = ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(isbn, "p1");
                com.quizlet.search.viewmodels.p pVar3 = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar3.getClass();
                Intrinsics.checkNotNullParameter(isbn, "isbn");
                kotlinx.coroutines.E.A(androidx.lifecycle.p0.j(pVar3), null, null, new C4803i(pVar3, jLongValue6, iIntValue3, isbn, null), 3);
                return Unit.a;
            case 8:
                String questionId = (String) obj;
                String slug = (String) obj2;
                int iIntValue4 = ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(questionId, "p0");
                Intrinsics.checkNotNullParameter(slug, "p1");
                com.quizlet.search.viewmodels.p pVar4 = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar4.getClass();
                Intrinsics.checkNotNullParameter(questionId, "questionId");
                Intrinsics.checkNotNullParameter(slug, "slug");
                kotlinx.coroutines.E.A(androidx.lifecycle.p0.j(pVar4), null, null, new C4800f(pVar4, questionId, iIntValue4, slug, null), 3);
                return Unit.a;
            default:
                EnumC4484g1 enumC4484g1 = (EnumC4484g1) obj;
                com.quizlet.generated.enums.Y0 y0 = (com.quizlet.generated.enums.Y0) obj2;
                EnumC4490i1 enumC4490i1 = (EnumC4490i1) obj3;
                com.quizlet.search.viewmodels.A a = (com.quizlet.search.viewmodels.A) this.receiver;
                kotlinx.coroutines.flow.s0 s0Var = a.n;
                do {
                    value = s0Var.getValue();
                    numTermsFilters = new SearchFilterNumTermsState(enumC4484g1);
                    creatorTypeFilter = new SearchFilterCreatorTypeState(y0);
                    contentTypeFilters = new SearchFilterContentTypeState(enumC4490i1);
                    ((SearchFiltersStates) value).getClass();
                    Intrinsics.checkNotNullParameter(numTermsFilters, "numTermsFilters");
                    Intrinsics.checkNotNullParameter(creatorTypeFilter, "creatorTypeFilter");
                    Intrinsics.checkNotNullParameter(contentTypeFilters, "contentTypeFilters");
                } while (!s0Var.k(value, new SearchFiltersStates(numTermsFilters, creatorTypeFilter, contentTypeFilters)));
                com.quizlet.search.paging.d dVar = a.l;
                if (dVar != null) {
                    dVar.b();
                }
                return Unit.a;
        }
    }
}
