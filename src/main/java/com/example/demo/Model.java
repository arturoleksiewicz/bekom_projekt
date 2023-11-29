package com.example.demo;
import jakarta.persistence.*;
import jakarta.persistence.Id;


@Entity
public class Model {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String nazwa;
    private Integer rokProdukcji;
    public Model(){}
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getNazwa() {
        return nazwa;
    }

    public void setNazwa(String nazwa) {
        this.nazwa = nazwa;
    }

    public Integer getRokProdukcji() {
        return rokProdukcji;
    }

    public void setRokProdukcji(Integer rokProdukcji) {
        this.rokProdukcji = rokProdukcji;
    }

    public Marka getMarka() {
        return marka;
    }

    public void setMarka(Marka marka) {
        this.marka = marka;
    }

    public Model(Long id, String nazwa, Integer rokProdukcji, Marka marka) {
        this.id = id;
        this.nazwa = nazwa;
        this.rokProdukcji = rokProdukcji;
        this.marka = marka;
    }

    @ManyToOne
    @JoinColumn(name = "marka_id", nullable = false)
    private Marka marka;

    // Gettery, settery, konstruktory
}