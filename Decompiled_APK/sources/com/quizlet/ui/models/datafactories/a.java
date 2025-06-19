package com.quizlet.ui.models.datafactories;

import com.quizlet.generated.enums.y1;
import com.quizlet.ui.models.content.listitem.d;
import com.quizlet.ui.models.content.listitem.e;
import com.quizlet.ui.models.content.listitem.f;
import com.quizlet.ui.models.content.listitem.g;
import com.quizlet.ui.models.content.listitem.h;
import com.quizlet.ui.models.content.listitem.i;
import com.quizlet.ui.models.content.listitem.j;
import com.quizlet.ui.models.content.listitem.l;
import com.quizlet.ui.models.content.listitem.m;
import com.quizlet.ui.models.content.listitem.n;
import com.quizlet.ui.models.content.listitem.p;
import com.quizlet.ui.models.content.listitem.q;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public static l a() {
        Intrinsics.checkNotNullParameter("Flashcard Set Title", "title");
        Intrinsics.checkNotNullParameter("Creator", "creatorName");
        d data = new d(10, 1L, "Flashcard Set Title", "Creator", false, false);
        y1 studyMaterialType = y1.SET;
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter("415", "materialId");
        Intrinsics.checkNotNullParameter("Flashcard Set Title", "name");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        return new l(data, "415", 0L, "Flashcard Set Title", studyMaterialType);
    }

    public static h b() {
        Intrinsics.checkNotNullParameter("Folder Title", "title");
        e data = new e(1L, "Folder Title");
        y1 studyMaterialType = y1.FOLDER;
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter("149565314", "materialId");
        Intrinsics.checkNotNullParameter("Folder Title", "name");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        return new h(data, "149565314", 0L, "Folder Title", studyMaterialType);
    }

    public static i c() {
        Intrinsics.checkNotNullParameter("uuid", "uuid");
        Intrinsics.checkNotNullParameter("Notes Title", "title");
        Intrinsics.checkNotNullParameter("Creator", "creatorName");
        f data = new f("uuid", "Notes Title", "Creator", false);
        y1 studyMaterialType = y1.NOTE;
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter("2568af64-d3bd-4ed6-9a2e-cfb08c28c0c1", "materialId");
        Intrinsics.checkNotNullParameter("Notes Title", "name");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        return new i(data, "2568af64-d3bd-4ed6-9a2e-cfb08c28c0c1", 0L, "Notes Title", studyMaterialType);
    }

    public static j d() {
        Intrinsics.checkNotNullParameter("uuid", "uuid");
        Intrinsics.checkNotNullParameter("Practice Test Title", "title");
        g data = new g("uuid", "Practice Test Title");
        y1 studyMaterialType = y1.PRACTICE_TEST;
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter("21e030eb-4433-4dd3-a2e9-9f458b0c0677", "materialId");
        Intrinsics.checkNotNullParameter("Practice Test Title", "name");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        return new j(data, "21e030eb-4433-4dd3-a2e9-9f458b0c0677", "Practice Test Title", studyMaterialType);
    }

    public static p e() {
        Intrinsics.checkNotNullParameter("isbn", "isbn");
        Intrinsics.checkNotNullParameter("Textbook Title", "title");
        Intrinsics.checkNotNullParameter("1st", "edition");
        Intrinsics.checkNotNullParameter("Author Name", "authors");
        return new p("isbn", "Textbook Title", "1st", "Author Name");
    }

    public static m f() {
        p textbookMetadata = e();
        Intrinsics.checkNotNullParameter("mediaExerciseId", "mediaExerciseId");
        Intrinsics.checkNotNullParameter("Exercise Name", "exercise");
        Intrinsics.checkNotNullParameter("Chapter 1", "chapter");
        Intrinsics.checkNotNullParameter(textbookMetadata, "textbookMetadata");
        q data = new q("mediaExerciseId", "Exercise Name", "Chapter 1", "Chapter Title", "Section 1", "Section Title", "Group Title", "1", textbookMetadata);
        y1 studyMaterialType = y1.TEXTBOOK_EXERCISE;
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter("aa5db078-b29adc9f-56ac-4aa0-9c13-10c701867987", "materialId");
        Intrinsics.checkNotNullParameter("Exercise Name", "name");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        return new m(data, "aa5db078-b29adc9f-56ac-4aa0-9c13-10c701867987", 0L, "Exercise Name", studyMaterialType);
    }

    public static n g() {
        p data = e();
        String name = data.b;
        y1 studyMaterialType = y1.TEXTBOOK;
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter("9781337561914", "materialId");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        return new n(data, "9781337561914", 0L, name, studyMaterialType);
    }
}
