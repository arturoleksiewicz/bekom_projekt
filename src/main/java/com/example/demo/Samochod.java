package com.example.demo;

import jakarta.persistence.*;
import jakarta.persistence.Id;

@Entity
@Table(name = "Samochody")
public class Samochod {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "marka_id", nullable = false)
    private Marka marka;

    @ManyToOne
    @JoinColumn(name = "model_id", nullable = false)
    private Model model;

    private Integer rokProdukcji;
    private Double cena;
    private Boolean dostepny;

    public Samochod() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Marka getMarka() {
        return marka;
    }

    public void setMarka(Marka marka) {
        this.marka = marka;
    }

    public Model getModel() {
        return model;
    }

    public void setModel(Model model) {
        this.model = model;
    }

    public Integer getRokProdukcji() {
        return rokProdukcji;
    }

    public void setRokProdukcji(Integer rokProdukcji) {
        this.rokProdukcji = rokProdukcji;
    }

    public Double getCena() {
        return cena;
    }

    public void setCena(Double cena) {
        this.cena = cena;
    }

    public Boolean getDostepny() {
        return dostepny;
    }

    public void setDostepny(Boolean dostepny) {
        this.dostepny = dostepny;
    }

    public Samochod(Long id, Marka marka, Model model, Integer rokProdukcji, Double cena, Boolean dostepny) {
        this.id = id;
        this.marka = marka;
        this.model = model;
        this.rokProdukcji = rokProdukcji;
        this.cena = cena;
        this.dostepny = dostepny;
    }
    // Gettery i settery
}
