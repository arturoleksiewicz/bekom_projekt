package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/klienci")
public class KlientController {

    @Autowired
    private KlientRepository klientRepository;

    @GetMapping
    public List<Klient> getAllKlienci() {
        return klientRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Klient> getKlientById(@PathVariable(value = "id") Long id) {
        return klientRepository.findById(id)
                .map(klient -> ResponseEntity.ok().body(klient))
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public Klient createKlient(@RequestBody Klient klient) {
        return klientRepository.save(klient);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Klient> updateKlient(@PathVariable(value = "id") Long id, @RequestBody Klient klientDetails) {
        return klientRepository.findById(id)
                .map(klient -> {
                    klient.setImie(klientDetails.getImie());
                    klient.setNazwisko(klientDetails.getNazwisko());
                    klient.setEmail(klientDetails.getEmail());
                    Klient updatedKlient = klientRepository.save(klient);
                    return ResponseEntity.ok().body(updatedKlient);
                }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteKlient(@PathVariable(value = "id") Long id) {
        return klientRepository.findById(id)
                .map(klient -> {
                    klientRepository.delete(klient);
                    return ResponseEntity.ok().build();
                }).orElse(ResponseEntity.notFound().build());
    }
}
