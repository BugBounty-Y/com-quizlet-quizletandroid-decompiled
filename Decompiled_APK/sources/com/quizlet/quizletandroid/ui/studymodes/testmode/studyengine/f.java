package com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine;

import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableDiagramShape;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableText;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f {
    public final boolean a;
    public final StudiableText b;
    public final StudiableImage c;
    public final StudiableAudio d;
    public final StudiableDiagramShape e;
    public final Long f;

    public /* synthetic */ f(boolean z, StudiableText studiableText, int i) {
        this(z, (i & 2) != 0 ? null : studiableText, null, null, null, null);
    }

    public final DBDiagramShape a() {
        Long l;
        StudiableDiagramShape studiableDiagramShape = this.e;
        if (studiableDiagramShape == null || (l = this.f) == null) {
            return null;
        }
        DBDiagramShape dBDiagramShape = new DBDiagramShape();
        dBDiagramShape.setTermId(l.longValue());
        dBDiagramShape.setShape(studiableDiagramShape.a);
        return dBDiagramShape;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && Intrinsics.b(this.b, fVar.b) && Intrinsics.b(this.c, fVar.c) && Intrinsics.b(this.d, fVar.d) && Intrinsics.b(this.e, fVar.e) && Intrinsics.b(this.f, fVar.f);
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        StudiableText studiableText = this.b;
        int iHashCode2 = (iHashCode + (studiableText == null ? 0 : studiableText.hashCode())) * 31;
        StudiableImage studiableImage = this.c;
        int iHashCode3 = (iHashCode2 + (studiableImage == null ? 0 : studiableImage.hashCode())) * 31;
        StudiableAudio studiableAudio = this.d;
        int iHashCode4 = (iHashCode3 + (studiableAudio == null ? 0 : studiableAudio.a.hashCode())) * 31;
        StudiableDiagramShape studiableDiagramShape = this.e;
        int iHashCode5 = (iHashCode4 + (studiableDiagramShape == null ? 0 : studiableDiagramShape.a.hashCode())) * 31;
        Long l = this.f;
        return iHashCode5 + (l != null ? l.hashCode() : 0);
    }

    public final String toString() {
        return "Answer(isCorrect=" + this.a + ", text=" + this.b + ", image=" + this.c + ", audio=" + this.d + ", diagramShape=" + this.e + ", shapeId=" + this.f + ")";
    }

    public f(boolean z, StudiableText studiableText, StudiableImage studiableImage, StudiableAudio studiableAudio, StudiableDiagramShape studiableDiagramShape, Long l) {
        this.a = z;
        this.b = studiableText;
        this.c = studiableImage;
        this.d = studiableAudio;
        this.e = studiableDiagramShape;
        this.f = l;
    }
}
