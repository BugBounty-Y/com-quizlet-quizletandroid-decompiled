package com.quizlet.eventlogger.features.explanations;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.study.StudyFunnelEventLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import com.quizlet.eventlogger.model.NavigationExplanationsEventLog;
import com.quizlet.generated.enums.EnumC4519s1;
import com.quizlet.generated.enums.EnumC4525u1;
import com.quizlet.generated.enums.M1;
import com.quizlet.generated.enums.w1;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ExplanationsLogger {

    @NotNull
    private static final String EXERCISE_NEXT_UP_TAPPED = "explanations_exercise_next_up_tapped";

    @NotNull
    private static final String EXPLANATIONS_FEEDBACK = "explanations_feedback";

    @NotNull
    private static final String EXPLANATIONS_METER_EXCEEDED = "explanations_meter_exceeded";

    @NotNull
    private static final String EXPLANATIONS_SHARE = "explanations_share";

    @NotNull
    private static final String METERED_EXPLANATIONS_PAYWALL_CTA_CLICK = "metered_explanations_paywall_cta_click";

    @NotNull
    private static final String METERED_EXPLANATIONS_PILL_VIEW = "metered_explanations_pill_view";

    @NotNull
    private static final String METER_EXPLANATIONS_TOC_COACHMARK_VIEW = "explanations_textbook_toc_view_solutions_coachmark";

    @NotNull
    private static final String SEARCH_RESULT_TAPPED = "search_result_tapped";

    @NotNull
    private static final String SOLUTION_SHOW_ALL_TAPPED = "explanations_solution_show_all_steps_tapped";

    @NotNull
    private static final String TEXTBOOK_TOC_CONTENT_ITEM_CLICK = "explanations_textbook_toc_click_content_item";

    @NotNull
    private static final String TEXTBOOK_TOC_EXERCISE_ITEM_CLICK = "explanations_textbook_toc_click_exercise_item";
    public static final /* synthetic */ int a = 0;

    @NotNull
    private final EventLogger eventLogger;

    @NotNull
    private final StudyFunnelEventLogger studyFunnelEventLogger;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    @Metadata
    public static abstract class EventData {

        @Metadata
        public static final class Exercise extends EventData {

            @NotNull
            private final String exerciseId;
            private final long id;

            @NotNull
            private final String isbn;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public Exercise(long j, @NotNull String isbn, @NotNull String exerciseId) {
                super(null);
                Intrinsics.checkNotNullParameter(isbn, "isbn");
                Intrinsics.checkNotNullParameter(exerciseId, "exerciseId");
                this.id = j;
                this.isbn = isbn;
                this.exerciseId = exerciseId;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (!(obj instanceof Exercise)) {
                    return false;
                }
                Exercise exercise = (Exercise) obj;
                return this.id == exercise.id && Intrinsics.b(this.isbn, exercise.isbn) && Intrinsics.b(this.exerciseId, exercise.exerciseId);
            }

            @NotNull
            public final String getExerciseId() {
                return this.exerciseId;
            }

            public final long getId() {
                return this.id;
            }

            @NotNull
            public final String getIsbn() {
                return this.isbn;
            }

            public final int hashCode() {
                return this.exerciseId.hashCode() + d0.e(Long.hashCode(this.id) * 31, 31, this.isbn);
            }

            public final String toString() {
                long j = this.id;
                String str = this.isbn;
                String str2 = this.exerciseId;
                StringBuilder sb = new StringBuilder("Exercise(id=");
                sb.append(j);
                sb.append(", isbn=");
                sb.append(str);
                return AbstractC0147y.g(sb, ", exerciseId=", str2, ")");
            }
        }

        @Metadata
        public static final class Metering extends EventData {

            @NotNull
            private final String modelId;
            private final int modelType;
            private final int numRemaining;
            private final int threshold;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public Metering(@NotNull String modelId, int i, int i2, int i3) {
                super(null);
                Intrinsics.checkNotNullParameter(modelId, "modelId");
                this.modelId = modelId;
                this.modelType = i;
                this.numRemaining = i2;
                this.threshold = i3;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (!(obj instanceof Metering)) {
                    return false;
                }
                Metering metering2 = (Metering) obj;
                return Intrinsics.b(this.modelId, metering2.modelId) && this.modelType == metering2.modelType && this.numRemaining == metering2.numRemaining && this.threshold == metering2.threshold;
            }

            @NotNull
            public final String getModelId() {
                return this.modelId;
            }

            public final int getModelType() {
                return this.modelType;
            }

            public final int getNumRemaining() {
                return this.numRemaining;
            }

            public final int getThreshold() {
                return this.threshold;
            }

            public final int hashCode() {
                return Integer.hashCode(this.threshold) + d0.b(this.numRemaining, d0.b(this.modelType, this.modelId.hashCode() * 31, 31), 31);
            }

            public final String toString() {
                return "Metering(modelId=" + this.modelId + ", modelType=" + this.modelType + ", numRemaining=" + this.numRemaining + ", threshold=" + this.threshold + ")";
            }
        }

        @Metadata
        public static final class Question extends EventData {

            @NotNull
            private final String id;

            @NotNull
            private final String slug;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public Question(@NotNull String id, @NotNull String slug) {
                super(null);
                Intrinsics.checkNotNullParameter(id, "id");
                Intrinsics.checkNotNullParameter(slug, "slug");
                this.id = id;
                this.slug = slug;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (!(obj instanceof Question)) {
                    return false;
                }
                Question question = (Question) obj;
                return Intrinsics.b(this.id, question.id) && Intrinsics.b(this.slug, question.slug);
            }

            @NotNull
            public final String getId() {
                return this.id;
            }

            @NotNull
            public final String getSlug() {
                return this.slug;
            }

            public final int hashCode() {
                return this.slug.hashCode() + (this.id.hashCode() * 31);
            }

            public final String toString() {
                return AbstractC0147y.e("Question(id=", this.id, ", slug=", this.slug, ")");
            }
        }

        @Metadata
        public static final class Textbook extends EventData {
            private final long id;

            @NotNull
            private final String isbn;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public Textbook(long j, @NotNull String isbn) {
                super(null);
                Intrinsics.checkNotNullParameter(isbn, "isbn");
                this.id = j;
                this.isbn = isbn;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (!(obj instanceof Textbook)) {
                    return false;
                }
                Textbook textbook = (Textbook) obj;
                return this.id == textbook.id && Intrinsics.b(this.isbn, textbook.isbn);
            }

            public final long getId() {
                return this.id;
            }

            @NotNull
            public final String getIsbn() {
                return this.isbn;
            }

            public final int hashCode() {
                return this.isbn.hashCode() + (Long.hashCode(this.id) * 31);
            }

            public final String toString() {
                return "Textbook(id=" + this.id + ", isbn=" + this.isbn + ")";
            }
        }

        public /* synthetic */ EventData(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private EventData() {
        }
    }

    @Metadata
    public static final class LandingPage {
        static {
            new LandingPage();
        }

        private LandingPage() {
        }
    }

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    @Metadata
    public static final class MeteringPlacement {
        private static final /* synthetic */ kotlin.enums.a $ENTRIES;
        private static final /* synthetic */ MeteringPlacement[] $VALUES;
        public static final MeteringPlacement a;
        public static final MeteringPlacement b;

        @NotNull
        private final M1 placement;

        static {
            MeteringPlacement meteringPlacement = new MeteringPlacement("QUESTION_DETAIL", 0, M1.QUESTION_DETAIL);
            a = meteringPlacement;
            MeteringPlacement meteringPlacement2 = new MeteringPlacement("TEXTBOOK_EXERCISE", 1, M1.TEXTBOOK_EXERCISE);
            b = meteringPlacement2;
            MeteringPlacement[] meteringPlacementArr = {meteringPlacement, meteringPlacement2};
            $VALUES = meteringPlacementArr;
            $ENTRIES = AbstractC3328d.f(meteringPlacementArr);
        }

        private MeteringPlacement(String str, int i, M1 m1) {
            this.placement = m1;
        }

        @NotNull
        public static kotlin.enums.a getEntries() {
            return $ENTRIES;
        }

        public static MeteringPlacement valueOf(String str) {
            return (MeteringPlacement) Enum.valueOf(MeteringPlacement.class, str);
        }

        public static MeteringPlacement[] values() {
            return (MeteringPlacement[]) $VALUES.clone();
        }

        @NotNull
        public final String getLoggingName() {
            return this.placement.a();
        }

        @NotNull
        public final M1 getPlacement() {
            return this.placement;
        }
    }

    static {
        new Companion(null);
    }

    public ExplanationsLogger(@NotNull EventLogger eventLogger, @NotNull StudyFunnelEventLogger studyFunnelEventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(studyFunnelEventLogger, "studyFunnelEventLogger");
        this.eventLogger = eventLogger;
        this.studyFunnelEventLogger = studyFunnelEventLogger;
    }

    public static void b(ExplanationsLogger explanationsLogger, EventData.Textbook eventData, int i) {
        UUID funnelId = UUID.randomUUID();
        explanationsLogger.getClass();
        Intrinsics.checkNotNullParameter(eventData, "eventData");
        Intrinsics.checkNotNullParameter(funnelId, "funnelId");
        StudyFunnelEventLogger.a(explanationsLogger.studyFunnelEventLogger, EnumC4519s1.CLICK, Long.valueOf(eventData.getId()), 14, funnelId, EnumC4525u1.EXPLANATIONS_QUESTION_DETAIL, w1.RECOMMENDED_TEXTBOOKS, 0, i, null, null, null, null, 3840);
    }

    public static void e(ExplanationsEventLog.Payload payload, EventData eventData) {
        if (eventData instanceof EventData.Exercise) {
            EventData.Exercise exercise = (EventData.Exercise) eventData;
            payload.c(exercise.getId(), exercise.getIsbn(), exercise.getExerciseId());
            return;
        }
        if (eventData instanceof EventData.Question) {
            EventData.Question question = (EventData.Question) eventData;
            payload.f(question.getId(), question.getSlug());
            return;
        }
        if (eventData instanceof EventData.Textbook) {
            EventData.Textbook textbook = (EventData.Textbook) eventData;
            payload.h(textbook.getId(), null, textbook.getIsbn(), null);
        } else if (!(eventData instanceof EventData.Metering)) {
            if (eventData != null) {
                throw new NoWhenBranchMatchedException();
            }
        } else {
            EventData.Metering metering2 = (EventData.Metering) eventData;
            payload.d(metering2.getModelType(), metering2.getNumRemaining(), metering2.getModelId(), metering2.getThreshold());
        }
    }

    public final void a(ExplanationsEventLog explanationsEventLog) {
        this.eventLogger.l(explanationsEventLog);
    }

    public final void c(String screenName, String str, String str2) {
        EventLogger eventLogger = this.eventLogger;
        NavigationExplanationsEventLog.b.getClass();
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        Intrinsics.checkNotNullParameter("click", "action");
        Intrinsics.checkNotNullParameter("clicked_explanations_card", "clickName");
        NavigationExplanationsEventLog navigationExplanationsEventLog = new NavigationExplanationsEventLog(new NavigationExplanationsEventLog.Payload(screenName, "explanations", "clicked_explanations_card", str, str2));
        navigationExplanationsEventLog.setAction("click");
        eventLogger.l(navigationExplanationsEventLog);
    }

    public final void d(String screenName, EventData eventData) {
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        ExplanationsEventLog.Companion companion = ExplanationsEventLog.b;
        a aVar = new a(3, eventData, this, screenName);
        companion.getClass();
        a(ExplanationsEventLog.Companion.a("visit_screen", aVar));
    }
}
