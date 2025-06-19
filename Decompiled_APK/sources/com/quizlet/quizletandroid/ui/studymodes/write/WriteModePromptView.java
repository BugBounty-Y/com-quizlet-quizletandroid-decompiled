package com.quizlet.quizletandroid.ui.studymodes.write;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.ScrollView;
import androidx.appcompat.widget.U0;
import androidx.compose.ui.platform.ViewTreeObserverOnGlobalLayoutListenerC0944h;
import com.google.android.gms.internal.mlkit_vision_barcode.B6;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.O1;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.common.views.ContentTextView;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import java.lang.reflect.InvocationTargetException;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class WriteModePromptView extends LinearLayout {
    public static final /* synthetic */ int W = 0;
    public final QFormField A;
    public final EditText B;
    public final com.quizlet.data.interactor.school.e C;
    public boolean D;
    public boolean E;
    public boolean F;
    public boolean G;
    public boolean H;
    public int I;
    public boolean J;
    public O1 K;
    public boolean L;
    public boolean M;
    public com.quizlet.quizletandroid.ui.common.dialogs.b V;
    public final com.quizlet.quizletandroid.managers.audio.h a;
    public final com.quizlet.quizletandroid.util.f b;
    public grading.a c;
    public final com.quizlet.qutils.image.loading.a d;
    public final io.ktor.client.plugins.api.d e;
    public j f;
    public DBTerm g;
    public final ContentTextView h;
    public final QButton i;
    public final QButton j;
    public final QButton k;
    public final QButton l;
    public final RelativeLayout m;
    public final FrameLayout n;
    public final QButton o;
    public final RelativeLayout p;
    public final RelativeLayout q;
    public final ContentTextView r;
    public final ScrollView s;
    public final ImageView t;
    public final QTextView u;
    public final LinearLayout v;
    public final RelativeLayout w;
    public final QTextView x;
    public final ContentTextView y;
    public final ImageView z;

    public WriteModePromptView(Context context) {
        this(context, null, 0);
    }

    public static void a(WriteModePromptView writeModePromptView, DBTerm dBTerm) {
        String definitionImageDefaultUrl = dBTerm.getDefinitionImageDefaultUrl(writeModePromptView.getResources().getDisplayMetrics().densityDpi);
        if (org.apache.commons.lang3.e.d(definitionImageDefaultUrl)) {
            ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) writeModePromptView.d).a(writeModePromptView.getContext()).p(definitionImageDefaultUrl).o(writeModePromptView.t);
            writeModePromptView.setImageViewLongClickListener(definitionImageDefaultUrl);
        }
    }

    private String getAnswer() {
        DBTerm dBTerm = this.g;
        if (dBTerm == null) {
            return null;
        }
        return O1.DEFINITION.equals(getPromptSide()) ? dBTerm.getWord() : dBTerm.getDefinition();
    }

    private String getAnswerLanguageCode() {
        O1 o1 = O1.WORD;
        if (o1.equals(getPromptSide())) {
            o1 = O1.DEFINITION;
        }
        DBTerm dBTerm = this.g;
        return dBTerm == null ? Locale.ENGLISH.getLanguage() : dBTerm.getLanguageCode(o1);
    }

    private String getLocalizedAnswerLabel() {
        DBTerm currentTerm = getCurrentTerm();
        if (currentTerm == null) {
            return "";
        }
        O1 o1 = O1.WORD;
        String languageCode = currentTerm.getLanguageCode(o1);
        String languageCode2 = currentTerm.getLanguageCode(O1.DEFINITION);
        com.quizlet.quizletandroid.util.f fVar = this.b;
        Context context = getContext();
        O1 termSide = getAnswerSide();
        fVar.getClass();
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(termSide, "termSide");
        boolean zIsEmpty = TextUtils.isEmpty(languageCode);
        int i = R.string.type_definition_identifier;
        if (zIsEmpty || TextUtils.isEmpty(languageCode2)) {
            if (termSide == o1) {
                i = R.string.type_term_identifier;
            }
            String string = context.getString(i);
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            String string2 = context.getString(R.string.type_term_or_definition_response_label, string);
            Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
            return string2;
        }
        String strA = fVar.a(termSide == o1 ? languageCode : languageCode2);
        if (strA != null && strA.length() != 0 && !"photo".equals(languageCode2) && !Intrinsics.b(languageCode, languageCode2)) {
            String string3 = context.getString(R.string.type_language_answer_response_label, strA);
            Intrinsics.d(string3);
            return string3;
        }
        if (termSide == o1) {
            i = R.string.type_term_identifier;
        }
        String string4 = context.getString(i);
        Intrinsics.checkNotNullExpressionValue(string4, "getString(...)");
        String string5 = context.getString(R.string.type_term_or_definition_response_label, string4);
        Intrinsics.d(string5);
        return string5;
    }

    private String getQuestion() {
        DBTerm dBTerm = this.g;
        if (dBTerm == null) {
            return null;
        }
        return O1.WORD.equals(getPromptSide()) ? dBTerm.getWord() : dBTerm.getDefinition();
    }

    private void setImageViewLongClickListener(String str) {
        this.z.setOnLongClickListener(new com.quizlet.quizletandroid.ui.group.classcontent.adapter.b(2, this, str));
    }

    public final void b(boolean z) {
        this.j.setVisibility(4);
        if (!z) {
            this.F = false;
        }
        if (!this.E) {
            O1 o1 = this.K;
            O1 o12 = O1.WORD;
            if (o1.equals(o12)) {
                o12 = O1.DEFINITION;
            }
            e(o12);
        }
        if (z) {
            this.E = true;
            this.G = true;
            this.A.setSuccess(getResources().getString(R.string.correct_answer));
            this.v.setVisibility(8);
            this.h.setVisibility(org.apache.commons.lang3.e.c(getQuestion()) ? 8 : 0);
            return;
        }
        int visibility = this.v.getVisibility();
        EditText editText = this.B;
        if (visibility != 0) {
            this.v.setVisibility(0);
            if (g()) {
                this.z.setVisibility(0);
            }
            if (editText.getText().length() > 0) {
                this.w.setVisibility(0);
                this.i.setVisibility(0);
                this.u.setText(editText.getText().toString());
                this.H = false;
            } else {
                this.w.setVisibility(8);
                this.i.setVisibility(4);
                this.H = true;
            }
            if (r1.heightPixels / getContext().getResources().getDisplayMetrics().density < 520.0f) {
                c();
            }
        }
        if (!this.E) {
            WriteModeActivity writeModeActivity = (WriteModeActivity) this.f;
            writeModeActivity.o1.c(writeModeActivity.q, writeModeActivity.g1, "view_correct_answer", this.g, this.K, null, getCurrentAnswerType(), null, null);
            editText.setText("");
        }
        this.A.setError(getResources().getString(R.string.write_correct_answer));
        this.E = true;
    }

    public final void c() {
        InputMethodManager inputMethodManager = (InputMethodManager) getContext().getSystemService("input_method");
        if (inputMethodManager != null) {
            inputMethodManager.hideSoftInputFromWindow(this.B.getWindowToken(), 0);
        }
    }

    public final void d(boolean z, Integer num) {
        j jVar = this.f;
        WriteModeActivity writeModeActivity = (WriteModeActivity) jVar;
        writeModeActivity.o1.c(writeModeActivity.q, writeModeActivity.g1, "answer", this.g, this.K, Boolean.valueOf(z), 5, null, num);
    }

    public final void e(O1 o1) {
        DBTerm dBTerm = this.g;
        if (!this.J || dBTerm == null) {
            return;
        }
        String audioUrl = dBTerm.getAudioUrl(o1);
        if (org.apache.commons.lang3.e.c(audioUrl)) {
            this.e.w(dBTerm, o1);
        } else {
            this.a.a(audioUrl).f(new com.quizlet.background.eventlogging.a(3), new com.quizlet.billing.subscriptions.c(2));
        }
    }

    public final void f(WriteStudyModeConfig writeStudyModeConfig, DBTerm dBTerm) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        setConfiguration(writeStudyModeConfig);
        this.g = dBTerm;
        this.E = false;
        this.F = true;
        this.G = false;
        this.D = false;
        this.A.setLabel(getResources().getString(R.string.type_answer_prompt));
        EditText editText = this.B;
        editText.setVisibility(0);
        this.i.setVisibility(4);
        this.j.setVisibility(0);
        this.v.setVisibility(8);
        this.h.setVisibility(!org.apache.commons.lang3.e.c(getQuestion()) ? 0 : 8);
        if (this.g != null) {
            String question = getQuestion();
            if (!g() || O1.WORD.equals(getPromptSide())) {
                this.z.setVisibility(8);
            } else {
                String definitionImageLargeUrl = this.g.getDefinitionImageLargeUrl();
                if (org.apache.commons.lang3.e.c(definitionImageLargeUrl)) {
                    definitionImageLargeUrl = this.g.getDefinitionImageDefaultUrl(getResources().getDisplayMetrics().densityDpi);
                }
                if (!org.apache.commons.lang3.e.c(definitionImageLargeUrl)) {
                    ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) this.d).a(getContext()).p(definitionImageLargeUrl).o(this.z);
                    setImageViewLongClickListener(definitionImageLargeUrl);
                    this.z.setVisibility(0);
                }
            }
            this.h.j(B6.e(this.g, getPromptSide()));
            this.h.setVisibility(!org.apache.commons.lang3.e.c(question) ? 0 : 8);
            if (org.apache.commons.lang3.e.c(question) || question.length() <= 50) {
                this.h.setTextSize(2, 30.0f);
            } else {
                this.h.setTextSize(2, 22.0f);
            }
            editText.setText("");
            editText.setHint("");
            QFormField qFormField = this.A;
            qFormField.t = 0;
            qFormField.r = false;
            qFormField.k(false);
            qFormField.i();
            this.A.setLabel(getLocalizedAnswerLabel());
            this.y.j(B6.e(this.g, getAnswerSide()));
            if (j(getAnswer())) {
                this.m.setVisibility(0);
                this.n.setVisibility(8);
                InputMethodManager inputMethodManager = (InputMethodManager) getContext().getSystemService("input_method");
                if (j(getAnswer())) {
                    editText.setVisibility(0);
                    editText.setFocusableInTouchMode(true);
                    editText.setFocusable(true);
                    editText.requestFocus();
                    editText.post(new f(this, 0));
                }
                if (inputMethodManager != null) {
                    inputMethodManager.showSoftInput(editText, 1);
                }
            } else {
                DBTerm dBTerm2 = this.g;
                if (dBTerm2 != null) {
                    String definitionImageLargeUrl2 = dBTerm2.getDefinitionImageLargeUrl();
                    if (org.apache.commons.lang3.e.d(definitionImageLargeUrl2) && g() && O1.WORD.equals(getPromptSide())) {
                        setImageViewLongClickListener(definitionImageLargeUrl2);
                        this.t.setVisibility(0);
                        ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) this.d).a(getContext()).p(definitionImageLargeUrl2).p(this.t, null, new g(this, dBTerm2));
                    } else {
                        this.t.setVisibility(8);
                    }
                    String answer = getAnswer();
                    this.r.j(B6.e(this.g, getAnswerSide()));
                    this.s.setVisibility((O1.DEFINITION.equals(getPromptSide()) || (answer != null && answer.length() > 0) || !this.g.hasDefinitionImage()) ? 0 : 8);
                    this.s.fullScroll(33);
                    this.p.setVisibility(0);
                    this.q.setVisibility(8);
                }
                this.m.setVisibility(8);
                this.n.setVisibility(0);
                c();
            }
            e(this.K);
        }
    }

    public final boolean g() {
        DBTerm dBTerm;
        return this.L && (dBTerm = this.g) != null && dBTerm.hasDefinitionImage();
    }

    public O1 getAnswerSide() {
        O1 o1 = O1.DEFINITION;
        return o1.equals(getPromptSide()) ? O1.WORD : o1;
    }

    public Integer getCurrentAnswerType() {
        return Integer.valueOf(j(getAnswer()) ? 1 : 5);
    }

    public DBTerm getCurrentTerm() {
        return this.g;
    }

    public O1 getPromptSide() {
        return this.K;
    }

    public final void h() {
        boolean z;
        String userSubmission = this.B.getText().toString();
        DBTerm dBTerm = this.g;
        O1 o1 = this.K;
        String correctAnswer = dBTerm.getWord() != null ? dBTerm.getWord() : "";
        String correctAnswer2 = dBTerm.getDefinition() != null ? dBTerm.getDefinition() : "";
        int i = i.a[o1.ordinal()];
        if (i == 1) {
            grading.core.h submissionContext = new grading.core.h(getAnswerLanguageCode(), dBTerm.getLanguageCode(O1.DEFINITION), correctAnswer2, new grading.core.d(false, false, false, false));
            grading.a aVar = this.c;
            aVar.getClass();
            Intrinsics.checkNotNullParameter(correctAnswer2, "correctAnswer");
            Intrinsics.checkNotNullParameter(userSubmission, "userSubmission");
            Intrinsics.checkNotNullParameter(submissionContext, "submissionContext");
            z = aVar.a(correctAnswer2, userSubmission, submissionContext).a;
        } else {
            if (i != 2) {
                throw new IllegalArgumentException("Unexpected prompt side: " + o1.name());
            }
            grading.core.h submissionContext2 = new grading.core.h(getAnswerLanguageCode(), dBTerm.getLanguageCode(O1.WORD), correctAnswer, new grading.core.d(false, false, false, false));
            grading.a aVar2 = this.c;
            aVar2.getClass();
            Intrinsics.checkNotNullParameter(correctAnswer, "correctAnswer");
            Intrinsics.checkNotNullParameter(userSubmission, "userSubmission");
            Intrinsics.checkNotNullParameter(submissionContext2, "submissionContext");
            z = aVar2.a(correctAnswer, userSubmission, submissionContext2).a;
        }
        if (!this.E) {
            WriteModeActivity writeModeActivity = (WriteModeActivity) this.f;
            writeModeActivity.o1.c(writeModeActivity.q, writeModeActivity.g1, "answer", this.g, this.K, Boolean.valueOf(z), 1, userSubmission, null);
        } else if (z) {
            WriteModeActivity writeModeActivity2 = (WriteModeActivity) this.f;
            writeModeActivity2.o1.c(writeModeActivity2.q, writeModeActivity2.g1, "submit_correction", this.g, this.K, null, getCurrentAnswerType(), null, null);
        }
        b(z);
        if (z) {
            i();
            com.quizlet.data.interactor.school.e eVar = this.C;
            eVar.getClass();
            eVar.a = System.currentTimeMillis();
            ((Handler) eVar.b).postDelayed((com.google.firebase.crashlytics.internal.common.i) eVar.c, 2000L);
        }
    }

    public final void i() {
        DBTerm dBTerm = this.g;
        if (this.D || dBTerm == null) {
            return;
        }
        this.D = true;
        j jVar = this.f;
        final long id = dBTerm.getId();
        final boolean z = this.F;
        final O1 o1 = this.K;
        final WriteModeActivity writeModeActivity = (WriteModeActivity) jVar;
        if (z) {
            writeModeActivity.X.add((DBTerm) writeModeActivity.c1.get(Long.valueOf(id)));
            writeModeActivity.d1++;
        } else {
            writeModeActivity.W.add((DBTerm) writeModeActivity.c1.get(Long.valueOf(id)));
            writeModeActivity.W(id);
        }
        writeModeActivity.w.b(writeModeActivity.J.u(new io.reactivex.rxjava3.functions.d() { // from class: com.quizlet.quizletandroid.ui.studymodes.write.b
            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                long id2;
                WriteModeActivity writeModeActivity2 = writeModeActivity;
                writeModeActivity2.getClass();
                DBSession dBSession = ((com.quizlet.features.infra.basestudy.data.models.dataproviders.a) obj).C;
                if (dBSession != null) {
                    id2 = dBSession.getId();
                } else {
                    timber.log.c.a.g("Failed to load session from onStudyModeDataReady", new Object[0]);
                    id2 = writeModeActivity2.O().getId();
                }
                long j = id2;
                long jLongValue = writeModeActivity2.u.f.getStudyableId().longValue();
                A1 a1 = A1.MOBILE_WRITE;
                int i = writeModeActivity2.e1;
                long personId = writeModeActivity2.x.getPersonId();
                long jCurrentTimeMillis = System.currentTimeMillis() / 1000;
                O1 o12 = o1;
                long j2 = id;
                boolean z2 = z;
                DBAnswer dBAnswer = new DBAnswer(j, jLongValue, j2, a1, i, z2 ? 1 : 0, personId, o12, jCurrentTimeMillis);
                Object[] objArr = {Long.valueOf(j2), Integer.valueOf(writeModeActivity2.e1), Boolean.valueOf(z2), Long.valueOf(j)};
                timber.log.a aVar = timber.log.c.a;
                aVar.a("Saving answer: %s, %s, %s, %s", objArr);
                writeModeActivity2.l1.c(dBAnswer);
                if (writeModeActivity2.M.size() == 0 && writeModeActivity2.V.size() == writeModeActivity2.X.size()) {
                    DBSession dBSession2 = writeModeActivity2.u.C;
                    if (dBSession2.hasEnded()) {
                        return;
                    }
                    aVar.a("Closing session", new Object[0]);
                    dBSession2.setEndedTimestampMs(System.currentTimeMillis());
                    dBSession2.setScore(writeModeActivity2.e1 + 1);
                    writeModeActivity2.j1.a(dBSession2);
                    com.quizlet.ads.d dVar = writeModeActivity2.v;
                    if (dVar != null) {
                        StringBuilder sb = new StringBuilder("RateUsPromoSessionCount_");
                        long j3 = dVar.a;
                        sb.append(j3);
                        String string = sb.toString();
                        SharedPreferences sharedPreferences = dVar.b;
                        int i2 = sharedPreferences.getInt(string, 0) + 1;
                        if (i2 > 3) {
                            return;
                        }
                        sharedPreferences.edit().putInt("RateUsPromoSessionCount_" + j3, i2).apply();
                    }
                }
            }
        }, new com.quizlet.billing.subscriptions.c(2), io.reactivex.rxjava3.internal.functions.d.c));
    }

    public final boolean j(String str) {
        if (!this.M) {
            return false;
        }
        if (str == null) {
            str = "";
        }
        return str.replaceAll("\\(.*\\) ?", "").length() > 0;
    }

    @Override // android.widget.LinearLayout, android.view.View
    public final void onMeasure(int i, int i2) {
        int size = View.MeasureSpec.getSize(i2);
        int height = getHeight();
        if (this.v.getVisibility() == 0) {
            if (r2.heightPixels / getContext().getResources().getDisplayMetrics().density < 520.0f && height > size) {
                this.w.setVisibility(8);
                this.x.setVisibility(8);
            } else if (height < size) {
                if (!this.H) {
                    this.w.setVisibility(0);
                }
                this.x.setVisibility(0);
            }
        }
        super.onMeasure(i, i2);
    }

    public void setConfiguration(WriteStudyModeConfig writeStudyModeConfig) {
        this.K = writeStudyModeConfig.a;
        this.M = writeStudyModeConfig.b;
        this.J = writeStudyModeConfig.c;
        this.L = writeStudyModeConfig.d;
    }

    public void setGrader(grading.a aVar) {
        this.c = aVar;
    }

    public void setImageOverlayListener(com.quizlet.quizletandroid.ui.common.dialogs.b bVar) {
        this.V = bVar;
    }

    public void setTermPromptListener(j jVar) {
        this.f = jVar;
    }

    public WriteModePromptView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public WriteModePromptView(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, 0);
        this.H = false;
        this.K = O1.DEFINITION;
        u uVar = (u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, context.getApplicationContext()));
        this.a = (com.quizlet.quizletandroid.managers.audio.h) uVar.f0.get();
        this.b = (com.quizlet.quizletandroid.util.f) uVar.a0.get();
        this.d = (com.quizlet.qutils.image.loading.a) uVar.s.get();
        this.e = uVar.g();
        View viewInflate = LayoutInflater.from(context).inflate(R.layout.write_prompt, (ViewGroup) this, false);
        addView(viewInflate);
        int i2 = R.id.correct_answer_container;
        if (((RelativeLayout) AbstractC3375o2.c(R.id.correct_answer_container, viewInflate)) != null) {
            i2 = R.id.learn_prompt_answer_textview;
            ContentTextView contentTextView = (ContentTextView) AbstractC3375o2.c(R.id.learn_prompt_answer_textview, viewInflate);
            if (contentTextView != null) {
                i2 = R.id.learn_prompt_button_container;
                if (((FrameLayout) AbstractC3375o2.c(R.id.learn_prompt_button_container, viewInflate)) != null) {
                    i2 = R.id.learn_prompt_correct_answer_header_textview;
                    QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.learn_prompt_correct_answer_header_textview, viewInflate);
                    if (qTextView != null) {
                        i2 = R.id.learn_prompt_do_not_know_button;
                        QButton qButton = (QButton) AbstractC3375o2.c(R.id.learn_prompt_do_not_know_button, viewInflate);
                        if (qButton != null) {
                            i2 = R.id.learn_prompt_override_button;
                            QButton qButton2 = (QButton) AbstractC3375o2.c(R.id.learn_prompt_override_button, viewInflate);
                            if (qButton2 != null) {
                                i2 = R.id.learn_prompt_question_area;
                                if (((RelativeLayout) AbstractC3375o2.c(R.id.learn_prompt_question_area, viewInflate)) != null) {
                                    i2 = R.id.learn_prompt_question_frame;
                                    if (((ScrollView) AbstractC3375o2.c(R.id.learn_prompt_question_frame, viewInflate)) != null) {
                                        i2 = R.id.learn_prompt_question_post_result_area;
                                        LinearLayout linearLayout = (LinearLayout) AbstractC3375o2.c(R.id.learn_prompt_question_post_result_area, viewInflate);
                                        if (linearLayout != null) {
                                            i2 = R.id.learn_prompt_question_text;
                                            ContentTextView contentTextView2 = (ContentTextView) AbstractC3375o2.c(R.id.learn_prompt_question_text, viewInflate);
                                            if (contentTextView2 != null) {
                                                i2 = R.id.learn_prompt_response_container;
                                                RelativeLayout relativeLayout = (RelativeLayout) AbstractC3375o2.c(R.id.learn_prompt_response_container, viewInflate);
                                                if (relativeLayout != null) {
                                                    i2 = R.id.learn_prompt_response_form_field;
                                                    QFormField qFormField = (QFormField) AbstractC3375o2.c(R.id.learn_prompt_response_form_field, viewInflate);
                                                    if (qFormField != null) {
                                                        i2 = R.id.learn_prompt_right_button;
                                                        QButton qButton3 = (QButton) AbstractC3375o2.c(R.id.learn_prompt_right_button, viewInflate);
                                                        if (qButton3 != null) {
                                                            i2 = R.id.learn_prompt_term_imageview;
                                                            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.learn_prompt_term_imageview, viewInflate);
                                                            if (imageView != null) {
                                                                i2 = R.id.learn_prompt_wrong_button;
                                                                QButton qButton4 = (QButton) AbstractC3375o2.c(R.id.learn_prompt_wrong_button, viewInflate);
                                                                if (qButton4 != null) {
                                                                    i2 = R.id.learn_prompt_your_answer_header_textview;
                                                                    if (((QTextView) AbstractC3375o2.c(R.id.learn_prompt_your_answer_header_textview, viewInflate)) != null) {
                                                                        i2 = R.id.learn_prompt_your_answer_textview;
                                                                        QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.learn_prompt_your_answer_textview, viewInflate);
                                                                        if (qTextView2 != null) {
                                                                            i2 = R.id.right_wrong_answer_container;
                                                                            RelativeLayout relativeLayout2 = (RelativeLayout) AbstractC3375o2.c(R.id.right_wrong_answer_container, viewInflate);
                                                                            if (relativeLayout2 != null) {
                                                                                ImageView imageView2 = (ImageView) AbstractC3375o2.c(R.id.right_wrong_answer_image, viewInflate);
                                                                                if (imageView2 != null) {
                                                                                    ContentTextView contentTextView3 = (ContentTextView) AbstractC3375o2.c(R.id.right_wrong_answer_text, viewInflate);
                                                                                    if (contentTextView3 != null) {
                                                                                        ScrollView scrollView = (ScrollView) AbstractC3375o2.c(R.id.right_wrong_answer_text_scroll, viewInflate);
                                                                                        if (scrollView == null) {
                                                                                            i2 = R.id.right_wrong_answer_text_scroll;
                                                                                        } else if (((LinearLayout) AbstractC3375o2.c(R.id.right_wrong_button_container, viewInflate)) != null) {
                                                                                            FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.right_wrong_container, viewInflate);
                                                                                            if (frameLayout != null) {
                                                                                                QButton qButton5 = (QButton) AbstractC3375o2.c(R.id.right_wrong_show_answer_button, viewInflate);
                                                                                                if (qButton5 != null) {
                                                                                                    RelativeLayout relativeLayout3 = (RelativeLayout) AbstractC3375o2.c(R.id.right_wrong_show_answer_container, viewInflate);
                                                                                                    if (relativeLayout3 != null) {
                                                                                                        RelativeLayout relativeLayout4 = (RelativeLayout) AbstractC3375o2.c(R.id.you_said_container, viewInflate);
                                                                                                        if (relativeLayout4 != null) {
                                                                                                            this.h = contentTextView2;
                                                                                                            this.i = qButton2;
                                                                                                            this.j = qButton;
                                                                                                            this.k = qButton3;
                                                                                                            this.l = qButton4;
                                                                                                            this.m = relativeLayout;
                                                                                                            this.n = frameLayout;
                                                                                                            this.o = qButton5;
                                                                                                            this.p = relativeLayout3;
                                                                                                            this.q = relativeLayout2;
                                                                                                            this.r = contentTextView3;
                                                                                                            this.s = scrollView;
                                                                                                            this.t = imageView2;
                                                                                                            this.u = qTextView2;
                                                                                                            this.v = linearLayout;
                                                                                                            this.w = relativeLayout4;
                                                                                                            this.x = qTextView;
                                                                                                            this.y = contentTextView;
                                                                                                            this.z = imageView;
                                                                                                            this.A = qFormField;
                                                                                                            EditText editText = qFormField.getEditText();
                                                                                                            this.B = editText;
                                                                                                            this.C = new com.quizlet.data.interactor.school.e(new f(this, 1));
                                                                                                            getViewTreeObserver().addOnGlobalLayoutListener(new ViewTreeObserverOnGlobalLayoutListenerC0944h(this, 2));
                                                                                                            final int i3 = 0;
                                                                                                            this.k.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.write.h
                                                                                                                public final /* synthetic */ WriteModePromptView b;

                                                                                                                {
                                                                                                                    this.b = this;
                                                                                                                }

                                                                                                                @Override // android.view.View.OnClickListener
                                                                                                                public final void onClick(View view) {
                                                                                                                    WriteModePromptView writeModePromptView = this.b;
                                                                                                                    switch (i3) {
                                                                                                                        case 0:
                                                                                                                            int i4 = WriteModePromptView.W;
                                                                                                                            writeModePromptView.b(true);
                                                                                                                            writeModePromptView.d(true, 3);
                                                                                                                            writeModePromptView.i();
                                                                                                                            writeModePromptView.C.c(true);
                                                                                                                            break;
                                                                                                                        case 1:
                                                                                                                            int i5 = WriteModePromptView.W;
                                                                                                                            writeModePromptView.b(false);
                                                                                                                            writeModePromptView.d(false, 4);
                                                                                                                            writeModePromptView.i();
                                                                                                                            writeModePromptView.C.c(true);
                                                                                                                            break;
                                                                                                                        case 2:
                                                                                                                            writeModePromptView.p.setVisibility(8);
                                                                                                                            writeModePromptView.q.setVisibility(0);
                                                                                                                            O1 o1 = writeModePromptView.K;
                                                                                                                            O1 o12 = O1.WORD;
                                                                                                                            if (o1.equals(o12)) {
                                                                                                                                o12 = O1.DEFINITION;
                                                                                                                            }
                                                                                                                            writeModePromptView.e(o12);
                                                                                                                            break;
                                                                                                                        case 3:
                                                                                                                            if (!writeModePromptView.G) {
                                                                                                                                writeModePromptView.F = true;
                                                                                                                                j jVar = writeModePromptView.f;
                                                                                                                                Integer currentAnswerType = writeModePromptView.getCurrentAnswerType();
                                                                                                                                WriteModeActivity writeModeActivity = (WriteModeActivity) jVar;
                                                                                                                                writeModeActivity.o1.c(writeModeActivity.q, writeModeActivity.g1, "override", writeModePromptView.g, writeModePromptView.K, null, currentAnswerType, null, null);
                                                                                                                                writeModePromptView.b(true);
                                                                                                                                writeModePromptView.i();
                                                                                                                                writeModePromptView.C.c(true);
                                                                                                                                break;
                                                                                                                            } else {
                                                                                                                                writeModePromptView.i();
                                                                                                                                writeModePromptView.C.c(true);
                                                                                                                                break;
                                                                                                                            }
                                                                                                                        default:
                                                                                                                            if (!writeModePromptView.G) {
                                                                                                                                writeModePromptView.d(false, 4);
                                                                                                                                writeModePromptView.b(false);
                                                                                                                                writeModePromptView.i();
                                                                                                                                break;
                                                                                                                            } else {
                                                                                                                                writeModePromptView.i();
                                                                                                                                break;
                                                                                                                            }
                                                                                                                    }
                                                                                                                }
                                                                                                            });
                                                                                                            final int i4 = 1;
                                                                                                            this.l.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.write.h
                                                                                                                public final /* synthetic */ WriteModePromptView b;

                                                                                                                {
                                                                                                                    this.b = this;
                                                                                                                }

                                                                                                                @Override // android.view.View.OnClickListener
                                                                                                                public final void onClick(View view) {
                                                                                                                    WriteModePromptView writeModePromptView = this.b;
                                                                                                                    switch (i4) {
                                                                                                                        case 0:
                                                                                                                            int i42 = WriteModePromptView.W;
                                                                                                                            writeModePromptView.b(true);
                                                                                                                            writeModePromptView.d(true, 3);
                                                                                                                            writeModePromptView.i();
                                                                                                                            writeModePromptView.C.c(true);
                                                                                                                            break;
                                                                                                                        case 1:
                                                                                                                            int i5 = WriteModePromptView.W;
                                                                                                                            writeModePromptView.b(false);
                                                                                                                            writeModePromptView.d(false, 4);
                                                                                                                            writeModePromptView.i();
                                                                                                                            writeModePromptView.C.c(true);
                                                                                                                            break;
                                                                                                                        case 2:
                                                                                                                            writeModePromptView.p.setVisibility(8);
                                                                                                                            writeModePromptView.q.setVisibility(0);
                                                                                                                            O1 o1 = writeModePromptView.K;
                                                                                                                            O1 o12 = O1.WORD;
                                                                                                                            if (o1.equals(o12)) {
                                                                                                                                o12 = O1.DEFINITION;
                                                                                                                            }
                                                                                                                            writeModePromptView.e(o12);
                                                                                                                            break;
                                                                                                                        case 3:
                                                                                                                            if (!writeModePromptView.G) {
                                                                                                                                writeModePromptView.F = true;
                                                                                                                                j jVar = writeModePromptView.f;
                                                                                                                                Integer currentAnswerType = writeModePromptView.getCurrentAnswerType();
                                                                                                                                WriteModeActivity writeModeActivity = (WriteModeActivity) jVar;
                                                                                                                                writeModeActivity.o1.c(writeModeActivity.q, writeModeActivity.g1, "override", writeModePromptView.g, writeModePromptView.K, null, currentAnswerType, null, null);
                                                                                                                                writeModePromptView.b(true);
                                                                                                                                writeModePromptView.i();
                                                                                                                                writeModePromptView.C.c(true);
                                                                                                                                break;
                                                                                                                            } else {
                                                                                                                                writeModePromptView.i();
                                                                                                                                writeModePromptView.C.c(true);
                                                                                                                                break;
                                                                                                                            }
                                                                                                                        default:
                                                                                                                            if (!writeModePromptView.G) {
                                                                                                                                writeModePromptView.d(false, 4);
                                                                                                                                writeModePromptView.b(false);
                                                                                                                                writeModePromptView.i();
                                                                                                                                break;
                                                                                                                            } else {
                                                                                                                                writeModePromptView.i();
                                                                                                                                break;
                                                                                                                            }
                                                                                                                    }
                                                                                                                }
                                                                                                            });
                                                                                                            editText.setOnEditorActionListener(new com.quizlet.login.recovery.forgotpassword.ui.b(this, 5));
                                                                                                            editText.addTextChangedListener(new U0(this, 4));
                                                                                                            final int i5 = 2;
                                                                                                            this.o.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.write.h
                                                                                                                public final /* synthetic */ WriteModePromptView b;

                                                                                                                {
                                                                                                                    this.b = this;
                                                                                                                }

                                                                                                                @Override // android.view.View.OnClickListener
                                                                                                                public final void onClick(View view) {
                                                                                                                    WriteModePromptView writeModePromptView = this.b;
                                                                                                                    switch (i5) {
                                                                                                                        case 0:
                                                                                                                            int i42 = WriteModePromptView.W;
                                                                                                                            writeModePromptView.b(true);
                                                                                                                            writeModePromptView.d(true, 3);
                                                                                                                            writeModePromptView.i();
                                                                                                                            writeModePromptView.C.c(true);
                                                                                                                            break;
                                                                                                                        case 1:
                                                                                                                            int i52 = WriteModePromptView.W;
                                                                                                                            writeModePromptView.b(false);
                                                                                                                            writeModePromptView.d(false, 4);
                                                                                                                            writeModePromptView.i();
                                                                                                                            writeModePromptView.C.c(true);
                                                                                                                            break;
                                                                                                                        case 2:
                                                                                                                            writeModePromptView.p.setVisibility(8);
                                                                                                                            writeModePromptView.q.setVisibility(0);
                                                                                                                            O1 o1 = writeModePromptView.K;
                                                                                                                            O1 o12 = O1.WORD;
                                                                                                                            if (o1.equals(o12)) {
                                                                                                                                o12 = O1.DEFINITION;
                                                                                                                            }
                                                                                                                            writeModePromptView.e(o12);
                                                                                                                            break;
                                                                                                                        case 3:
                                                                                                                            if (!writeModePromptView.G) {
                                                                                                                                writeModePromptView.F = true;
                                                                                                                                j jVar = writeModePromptView.f;
                                                                                                                                Integer currentAnswerType = writeModePromptView.getCurrentAnswerType();
                                                                                                                                WriteModeActivity writeModeActivity = (WriteModeActivity) jVar;
                                                                                                                                writeModeActivity.o1.c(writeModeActivity.q, writeModeActivity.g1, "override", writeModePromptView.g, writeModePromptView.K, null, currentAnswerType, null, null);
                                                                                                                                writeModePromptView.b(true);
                                                                                                                                writeModePromptView.i();
                                                                                                                                writeModePromptView.C.c(true);
                                                                                                                                break;
                                                                                                                            } else {
                                                                                                                                writeModePromptView.i();
                                                                                                                                writeModePromptView.C.c(true);
                                                                                                                                break;
                                                                                                                            }
                                                                                                                        default:
                                                                                                                            if (!writeModePromptView.G) {
                                                                                                                                writeModePromptView.d(false, 4);
                                                                                                                                writeModePromptView.b(false);
                                                                                                                                writeModePromptView.i();
                                                                                                                                break;
                                                                                                                            } else {
                                                                                                                                writeModePromptView.i();
                                                                                                                                break;
                                                                                                                            }
                                                                                                                    }
                                                                                                                }
                                                                                                            });
                                                                                                            final int i6 = 3;
                                                                                                            this.i.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.write.h
                                                                                                                public final /* synthetic */ WriteModePromptView b;

                                                                                                                {
                                                                                                                    this.b = this;
                                                                                                                }

                                                                                                                @Override // android.view.View.OnClickListener
                                                                                                                public final void onClick(View view) {
                                                                                                                    WriteModePromptView writeModePromptView = this.b;
                                                                                                                    switch (i6) {
                                                                                                                        case 0:
                                                                                                                            int i42 = WriteModePromptView.W;
                                                                                                                            writeModePromptView.b(true);
                                                                                                                            writeModePromptView.d(true, 3);
                                                                                                                            writeModePromptView.i();
                                                                                                                            writeModePromptView.C.c(true);
                                                                                                                            break;
                                                                                                                        case 1:
                                                                                                                            int i52 = WriteModePromptView.W;
                                                                                                                            writeModePromptView.b(false);
                                                                                                                            writeModePromptView.d(false, 4);
                                                                                                                            writeModePromptView.i();
                                                                                                                            writeModePromptView.C.c(true);
                                                                                                                            break;
                                                                                                                        case 2:
                                                                                                                            writeModePromptView.p.setVisibility(8);
                                                                                                                            writeModePromptView.q.setVisibility(0);
                                                                                                                            O1 o1 = writeModePromptView.K;
                                                                                                                            O1 o12 = O1.WORD;
                                                                                                                            if (o1.equals(o12)) {
                                                                                                                                o12 = O1.DEFINITION;
                                                                                                                            }
                                                                                                                            writeModePromptView.e(o12);
                                                                                                                            break;
                                                                                                                        case 3:
                                                                                                                            if (!writeModePromptView.G) {
                                                                                                                                writeModePromptView.F = true;
                                                                                                                                j jVar = writeModePromptView.f;
                                                                                                                                Integer currentAnswerType = writeModePromptView.getCurrentAnswerType();
                                                                                                                                WriteModeActivity writeModeActivity = (WriteModeActivity) jVar;
                                                                                                                                writeModeActivity.o1.c(writeModeActivity.q, writeModeActivity.g1, "override", writeModePromptView.g, writeModePromptView.K, null, currentAnswerType, null, null);
                                                                                                                                writeModePromptView.b(true);
                                                                                                                                writeModePromptView.i();
                                                                                                                                writeModePromptView.C.c(true);
                                                                                                                                break;
                                                                                                                            } else {
                                                                                                                                writeModePromptView.i();
                                                                                                                                writeModePromptView.C.c(true);
                                                                                                                                break;
                                                                                                                            }
                                                                                                                        default:
                                                                                                                            if (!writeModePromptView.G) {
                                                                                                                                writeModePromptView.d(false, 4);
                                                                                                                                writeModePromptView.b(false);
                                                                                                                                writeModePromptView.i();
                                                                                                                                break;
                                                                                                                            } else {
                                                                                                                                writeModePromptView.i();
                                                                                                                                break;
                                                                                                                            }
                                                                                                                    }
                                                                                                                }
                                                                                                            });
                                                                                                            final int i7 = 4;
                                                                                                            this.j.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.write.h
                                                                                                                public final /* synthetic */ WriteModePromptView b;

                                                                                                                {
                                                                                                                    this.b = this;
                                                                                                                }

                                                                                                                @Override // android.view.View.OnClickListener
                                                                                                                public final void onClick(View view) {
                                                                                                                    WriteModePromptView writeModePromptView = this.b;
                                                                                                                    switch (i7) {
                                                                                                                        case 0:
                                                                                                                            int i42 = WriteModePromptView.W;
                                                                                                                            writeModePromptView.b(true);
                                                                                                                            writeModePromptView.d(true, 3);
                                                                                                                            writeModePromptView.i();
                                                                                                                            writeModePromptView.C.c(true);
                                                                                                                            break;
                                                                                                                        case 1:
                                                                                                                            int i52 = WriteModePromptView.W;
                                                                                                                            writeModePromptView.b(false);
                                                                                                                            writeModePromptView.d(false, 4);
                                                                                                                            writeModePromptView.i();
                                                                                                                            writeModePromptView.C.c(true);
                                                                                                                            break;
                                                                                                                        case 2:
                                                                                                                            writeModePromptView.p.setVisibility(8);
                                                                                                                            writeModePromptView.q.setVisibility(0);
                                                                                                                            O1 o1 = writeModePromptView.K;
                                                                                                                            O1 o12 = O1.WORD;
                                                                                                                            if (o1.equals(o12)) {
                                                                                                                                o12 = O1.DEFINITION;
                                                                                                                            }
                                                                                                                            writeModePromptView.e(o12);
                                                                                                                            break;
                                                                                                                        case 3:
                                                                                                                            if (!writeModePromptView.G) {
                                                                                                                                writeModePromptView.F = true;
                                                                                                                                j jVar = writeModePromptView.f;
                                                                                                                                Integer currentAnswerType = writeModePromptView.getCurrentAnswerType();
                                                                                                                                WriteModeActivity writeModeActivity = (WriteModeActivity) jVar;
                                                                                                                                writeModeActivity.o1.c(writeModeActivity.q, writeModeActivity.g1, "override", writeModePromptView.g, writeModePromptView.K, null, currentAnswerType, null, null);
                                                                                                                                writeModePromptView.b(true);
                                                                                                                                writeModePromptView.i();
                                                                                                                                writeModePromptView.C.c(true);
                                                                                                                                break;
                                                                                                                            } else {
                                                                                                                                writeModePromptView.i();
                                                                                                                                writeModePromptView.C.c(true);
                                                                                                                                break;
                                                                                                                            }
                                                                                                                        default:
                                                                                                                            if (!writeModePromptView.G) {
                                                                                                                                writeModePromptView.d(false, 4);
                                                                                                                                writeModePromptView.b(false);
                                                                                                                                writeModePromptView.i();
                                                                                                                                break;
                                                                                                                            } else {
                                                                                                                                writeModePromptView.i();
                                                                                                                                break;
                                                                                                                            }
                                                                                                                    }
                                                                                                                }
                                                                                                            });
                                                                                                            return;
                                                                                                        }
                                                                                                        i2 = R.id.you_said_container;
                                                                                                    } else {
                                                                                                        i2 = R.id.right_wrong_show_answer_container;
                                                                                                    }
                                                                                                } else {
                                                                                                    i2 = R.id.right_wrong_show_answer_button;
                                                                                                }
                                                                                            } else {
                                                                                                i2 = R.id.right_wrong_container;
                                                                                            }
                                                                                        } else {
                                                                                            i2 = R.id.right_wrong_button_container;
                                                                                        }
                                                                                    } else {
                                                                                        i2 = R.id.right_wrong_answer_text;
                                                                                    }
                                                                                } else {
                                                                                    i2 = R.id.right_wrong_answer_image;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i2)));
    }
}
